"""证据入口：原始字节 -> 领域记录。

进入领域状态之前，文件依次经过：

1. UTF-8 与严格 JSON 结构检查（重复键、尾随内容在这一阶段拒绝）；
2. 字段合同检查（未知字段、类型、枚举、非法时间在这一阶段拒绝）；
3. 登记索引检查（同一内容哈希幂等；同名异内容暂停关联）。

任何一步失败都形成 :class:`QuarantineEntry`，其中保留原始字节、SHA-256
摘要以及全部可定位问题，不产生任何领域状态变更。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .errors import Problem, SchemaRejected, StrictJsonError
from .strictjson import Node, parse_bytes
from .timeutil import parse_instant

# ---------------------------------------------------------------------------
# 轻量结构校验框架（直接消费带位置的 Node，问题可定位到行列）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Field:
    kind: str  # string|integer|number|boolean|object|array|instant
    required: bool = True
    enum: tuple[Any, ...] | None = None
    fields: dict[str, "Field"] | None = None  # object 子字段
    item_fields: dict[str, "Field"] | None = None  # array 元素为对象时的形状


def _type_ok(node: Node, kind: str) -> bool:
    if kind == "string":
        return node.kind == "string"
    if kind == "integer":
        return node.kind == "number" and isinstance(node.value, int)
    if kind == "number":
        return node.kind == "number"
    if kind == "boolean":
        return node.kind == "boolean"
    if kind == "object":
        return node.kind == "object"
    if kind == "array":
        return node.kind == "array"
    if kind == "instant":
        return node.kind == "string"
    return False


def check_shape(node: Node, spec: dict[str, Field], pointer: str = "") -> list[Problem]:
    """按 spec 校验对象节点，收集全部问题（未知字段、缺字段、类型、枚举、时间）。"""

    problems: list[Problem] = []
    if node.kind != "object":
        problems.append(
            Problem(
                "type_mismatch",
                f"期望对象，实际为 {node.kind}",
                node.line,
                node.column,
                pointer or "/",
            )
        )
        return problems
    members: dict[str, Node] = node.value
    for key, child in members.items():
        if key not in spec:
            problems.append(
                Problem(
                    "unknown_field",
                    f"未知字段 {key!r}：字段合同为封闭集合，禁止前向/拼写错误字段静默入库",
                    child.line,
                    child.column,
                    f"{pointer}/{key}",
                )
            )
    for key, f in spec.items():
        child = members.get(key)
        if child is None:
            if f.required:
                problems.append(
                    Problem(
                        "missing_field",
                        f"缺少必填字段 {key!r}",
                        node.line,
                        node.column,
                        f"{pointer}/{key}",
                    )
                )
            continue
        child_pointer = f"{pointer}/{key}"
        if not _type_ok(child, f.kind):
            problems.append(
                Problem(
                    "type_mismatch",
                    f"字段 {key!r} 期望 {f.kind}，实际为 {child.kind}",
                    child.line,
                    child.column,
                    child_pointer,
                )
            )
            continue
        if f.kind == "instant":
            try:
                parse_instant(child.value)
            except ValueError as exc:
                problems.append(
                    Problem("invalid_time", f"字段 {key!r} 时间非法: {exc}",
                            child.line, child.column, child_pointer)
                )
        if f.enum is not None and child.value not in f.enum:
            problems.append(
                Problem(
                    "invalid_value",
                    f"字段 {key!r} 只允许 {list(f.enum)}，得到 {child.value!r}",
                    child.line,
                    child.column,
                    child_pointer,
                )
            )
        if f.kind == "object" and f.fields is not None:
            problems.extend(check_shape(child, f.fields, child_pointer))
        if f.kind == "array" and f.item_fields is not None:
            for index, element in enumerate(child.value):
                problems.extend(
                    check_shape(element, f.item_fields, f"{child_pointer}/{index}")
                )
    return problems


# ---------------------------------------------------------------------------
# 入口记录与隔离记录
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntakeRecord:
    """最小字段合同对应的领域记录（保持既有标识与时间含义）。"""

    schema_version: int
    record_id: str
    domain: str
    occurred_at: str
    revision: int
    source: str
    file_name: str
    byte_sha256: str


@dataclass(frozen=True)
class QuarantineEntry:
    """被拒绝文件的隔离留存：原始字节、摘要、阶段与全部可定位问题。"""

    file_name: str
    byte_sha256: str
    byte_length: int
    raw: bytes
    received_at: datetime
    stage: str  # json | schema | registry
    code: str
    problems: tuple[Problem, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "byte_sha256": self.byte_sha256,
            "byte_length": self.byte_length,
            "received_at": self.received_at.isoformat(),
            "stage": self.stage,
            "code": self.code,
            "problems": [
                {
                    "code": p.code,
                    "message": p.message,
                    "line": p.line,
                    "column": p.column,
                    "pointer": p.pointer,
                }
                for p in self.problems
            ],
        }


@dataclass(frozen=True)
class IngestResult:
    status: str  # accepted | duplicate | quarantined
    record: Any = None
    entry: QuarantineEntry | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("accepted", "duplicate")


_ENVELOPE_SPEC: dict[str, Field] = {
    "schema_version": Field("integer"),
    "record_id": Field("string"),
    "domain": Field("string"),
    "occurred_at": Field("instant"),
    "revision": Field("integer"),
    "source": Field("string"),
}


def validate_envelope(node: Node) -> IntakeRecord:
    """最小合同校验，额外拒绝非正版本/空标识/domain 错配。"""

    problems = check_shape(node, _ENVELOPE_SPEC)
    if not problems:
        values = {k: v.value for k, v in node.value.items()}
        if values["schema_version"] != 1:
            problems.append(Problem("invalid_value",
                                    f"schema_version 仅支持 1，得到 {values['schema_version']}",
                                    node.line, node.column, "/schema_version"))
        if not values["record_id"].strip():
            problems.append(Problem("invalid_value", "record_id 不允许为空字符串",
                                    node.line, node.column, "/record_id"))
        if values["domain"] != "fungus_chain":
            problems.append(Problem("invalid_value",
                                    f"domain 必须为 fungus_chain，得到 {values['domain']!r}",
                                    node.line, node.column, "/domain"))
        if values["revision"] < 1:
            problems.append(Problem("invalid_value", "revision 必须 >= 1",
                                    node.line, node.column, "/revision"))
        if not values["source"].strip():
            problems.append(Problem("invalid_value", "source 不允许为空字符串",
                                    node.line, node.column, "/source"))
    if problems:
        raise SchemaRejected(problems)
    values = {k: v.value for k, v in node.value.items()}
    return IntakeRecord(
        schema_version=values["schema_version"],
        record_id=values["record_id"],
        domain=values["domain"],
        occurred_at=values["occurred_at"],
        revision=values["revision"],
        source=values["source"],
        file_name="",
        byte_sha256="",
    )


# ---------------------------------------------------------------------------
# 登记台账：内容哈希幂等 + 同名异内容暂停
# ---------------------------------------------------------------------------

Validator = Callable[[Node], Any]


@dataclass
class _Admission:
    file_name: str
    raw: bytes
    digest: str
    received_at: datetime
    record: Any


class IntakeRegistry:
    """以原始字节为单位的登记台账。

    ``validator`` 把语法节点变成领域记录（失败抛 :class:`SchemaRejected`）。
    台账本身只管三件与内容无关的事：哈希幂等、同名异内容暂停、隔离留存。
    """

    def __init__(self, validator: Validator = validate_envelope):
        self._validator = validator
        self._accepted_hashes: dict[str, Any] = {}
        self._name_to_hash: dict[str, str] = {}
        self._held_names: set[str] = set()
        self._quarantined_hashes: dict[str, QuarantineEntry] = {}
        self.quarantine: list[QuarantineEntry] = []

    # -- 阶段 1/2/3：准备（不产生已接受状态） -------------------------------

    def prepare(
        self,
        raw: bytes,
        file_name: str,
        received_at: datetime | None = None,
    ) -> tuple[_Admission | None, IngestResult]:
        received_at = received_at or datetime.now(timezone.utc)
        digest = hashlib.sha256(raw).hexdigest()

        if digest in self._accepted_hashes:
            # 同一文件原样重送：识别为既有登记，绝不重复登记。
            return None, IngestResult("duplicate", record=self._accepted_hashes[digest])
        if digest in self._quarantined_hashes:
            return None, IngestResult("quarantined", entry=self._quarantined_hashes[digest])

        if file_name in self._held_names:
            entry = self._quarantine(
                raw, file_name, digest, received_at, stage="registry",
                code="name_hold",
                problems=[Problem(
                    "name_hold",
                    f"文件名 {file_name!r} 因此前同名异内容已暂停关联，"
                    "需人工裁决后才能恢复登记",
                )],
            )
            return None, IngestResult("quarantined", entry=entry)

        try:
            node = parse_bytes(raw)
        except StrictJsonError as exc:
            entry = self._quarantine(
                raw, file_name, digest, received_at,
                stage="json", code=exc.problems[0].code, problems=list(exc.problems),
            )
            return None, IngestResult("quarantined", entry=entry)

        try:
            record = self._validator(node)
        except SchemaRejected as exc:
            entry = self._quarantine(
                raw, file_name, digest, received_at,
                stage="schema", code=exc.problems[0].code, problems=list(exc.problems),
            )
            return None, IngestResult("quarantined", entry=entry)

        prior_hash = self._name_to_hash.get(file_name)
        if prior_hash is not None and prior_hash != digest:
            entry = self._quarantine(
                raw, file_name, digest, received_at, stage="registry",
                code="name_content_conflict",
                problems=[Problem(
                    "name_content_conflict",
                    (
                        f"文件名 {file_name!r} 已对应内容 {prior_hash[:12]}…，"
                        f"本次内容为 {digest[:12]}…；文件名相同但内容不同，暂停关联，"
                        "新旧两份字节均保留待人工裁决"
                    ),
                )],
            )
            self._held_names.add(file_name)
            return None, IngestResult("quarantined", entry=entry)

        return _Admission(file_name, raw, digest, received_at, record), IngestResult("accepted", record=record)

    # -- 阶段 4：领域语义成功后提交 / 失败时隔离 -----------------------------

    def commit(self, admission: _Admission) -> IngestResult:
        record = admission.record
        if isinstance(record, IntakeRecord):
            record = replace(record, file_name=admission.file_name, byte_sha256=admission.digest)
        self._accepted_hashes[admission.digest] = record
        self._name_to_hash[admission.file_name] = admission.digest
        return IngestResult("accepted", record=record)

    def reject_semantic(
        self, admission: _Admission, stage: str, problems: list[Problem]
    ) -> IngestResult:
        entry = self._quarantine(
            admission.raw, admission.file_name, admission.digest,
            admission.received_at, stage=stage, code=problems[0].code, problems=problems,
        )
        return IngestResult("quarantined", entry=entry)

    def restore_quarantine(self, entry: QuarantineEntry) -> None:
        """WAL 重放时重建隔离台账。"""

        self._quarantined_hashes[entry.byte_sha256] = entry
        self.quarantine.append(entry)
        if entry.code == "name_content_conflict":
            self._held_names.add(entry.file_name)

    def restore_accepted(self, file_name: str, digest: str, record: Any) -> None:
        """WAL 重放时重建已接受索引（领域状态由各模块另行重放）。"""

        self._accepted_hashes[digest] = record
        self._name_to_hash[file_name] = digest

    def _quarantine(
        self, raw: bytes, file_name: str, digest: str, received_at: datetime,
        *, stage: str, code: str, problems: list[Problem],
    ) -> QuarantineEntry:
        entry = QuarantineEntry(
            file_name=file_name,
            byte_sha256=digest,
            byte_length=len(raw),
            raw=raw,
            received_at=received_at,
            stage=stage,
            code=code,
            problems=tuple(problems),
        )
        self.quarantine.append(entry)
        self._quarantined_hashes[digest] = entry
        return entry

    def release_hold(self, file_name: str) -> None:
        """人工裁决后解除文件名暂停。"""

        self._held_names.discard(file_name)

    # -- 便捷入口 -----------------------------------------------------------

    def ingest_bytes(self, raw: bytes, file_name: str) -> IngestResult:
        admission, result = self.prepare(raw, file_name)
        if admission is None:
            return result
        return self.commit(admission)

    def ingest_file(self, path: Path) -> IngestResult:
        return self.ingest_bytes(path.read_bytes(), path.name)
