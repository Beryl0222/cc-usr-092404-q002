"""联检保管链台账。

台账只接受经过 :mod:`fungus_chain.ingress` 严格解析与
:mod:`fungus_chain.commands` 模式校验的命令文件，并维护以下不变量：

* **证据幂等**：原始字节 SHA-256 相同的重送直接返回首次登记位置，不再
  产生任何领域效果；文件名相同但内容不同时暂停关联（hold），不登记。
* **父子数量守恒**：父样初始量 == 父样剩余量 + 全部直系子样分配量；
  对整棵分样树，初始量 == 各节点当前剩余量 + 全部已耗用量。
* **耗用一次性**：同一样本的同一联检项目只能耗用一次，复测必须走补样。
* **结论路由**：晚到结果只能更新事件内依赖该项目、且尚未签发的结论；
  已签发版本不可变，只追加更正与接收回执。
* **危急通知去重**：通知绑定台账事件序号，恢复或重放不会重复发出。

所有改变状态的动作都向只追加的保管链事件流写入一条记录，记录带来源
文件名、字节摘要与来源消息编号。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .commands import (
    CMD_CONSUME,
    CMD_CREATE_CONCLUSION,
    CMD_INTAKE,
    CMD_ISSUE_CONCLUSION,
    CMD_RESULT,
    CMD_REVISE_CONCLUSION,
    CMD_SPLIT,
    CMD_SUPPLEMENT,
    PANEL_TESTS,
    validate_command,
)
from .ingress import (
    QuarantineRecord,
    _sort_issues,
    make_quarantine,
    parse_document,
)

# --------------------------------------------------------------------------
# 记录类型
# --------------------------------------------------------------------------


@dataclass
class Sample:
    sample_id: str
    incident_id: str
    specimen: str
    tests: tuple[str, ...]
    initial_quantity: int
    quantity_remaining: int
    unit: str
    parent_sample_id: str | None = None
    root_sample_id: str | None = None
    origin: str = "intake"  # intake | split | supplement
    children: list[str] = field(default_factory=list)
    consumed_for: dict[str, int] = field(default_factory=dict)  # test -> qty

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "incident_id": self.incident_id,
            "specimen": self.specimen,
            "tests": list(self.tests),
            "initial_quantity": self.initial_quantity,
            "quantity_remaining": self.quantity_remaining,
            "unit": self.unit,
            "parent_sample_id": self.parent_sample_id,
            "root_sample_id": self.root_sample_id,
            "origin": self.origin,
            "children": list(self.children),
            "consumed_for": dict(self.consumed_for),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Sample:
        return cls(
            sample_id=data["sample_id"],
            incident_id=data["incident_id"],
            specimen=data["specimen"],
            tests=tuple(data["tests"]),
            initial_quantity=data["initial_quantity"],
            quantity_remaining=data["quantity_remaining"],
            unit=data["unit"],
            parent_sample_id=data.get("parent_sample_id"),
            root_sample_id=data.get("root_sample_id"),
            origin=data.get("origin", "intake"),
            children=list(data.get("children", [])),
            consumed_for=dict(data.get("consumed_for", {})),
        )


@dataclass(frozen=True)
class ResultRecord:
    sample_id: str
    test: str
    analyte: str
    result: str
    critical: bool
    version: int
    source_message_id: str
    source_sha256: str
    recorded_at: str

    def key(self) -> tuple[str, str]:
        return (self.sample_id, self.test)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "test": self.test,
            "analyte": self.analyte,
            "result": self.result,
            "critical": self.critical,
            "version": self.version,
            "source_message_id": self.source_message_id,
            "source_sha256": self.source_sha256,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResultRecord:
        return cls(**data)


@dataclass(frozen=True)
class ConclusionVersion:
    revision: int
    kind: str  # create | revise | result_update
    content: str
    recorded_at: str
    source_message_id: str
    source_sha256: str
    results: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "kind": self.kind,
            "content": self.content,
            "recorded_at": self.recorded_at,
            "source_message_id": self.source_message_id,
            "source_sha256": self.source_sha256,
            "results": list(self.results),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConclusionVersion:
        return cls(
            revision=data["revision"],
            kind=data["kind"],
            content=data["content"],
            recorded_at=data["recorded_at"],
            source_message_id=data["source_message_id"],
            source_sha256=data["source_sha256"],
            results=tuple(data.get("results", [])),
        )


@dataclass(frozen=True)
class Correction:
    """已签发结论的追加更正；接收回执内嵌并单独入账。"""

    correction_id: str
    sample_id: str
    test: str
    analyte: str
    result: str
    critical: bool
    source_message_id: str
    source_sha256: str
    received_at: str
    receipt_id: str
    receipt_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "correction_id": self.correction_id,
            "sample_id": self.sample_id,
            "test": self.test,
            "analyte": self.analyte,
            "result": self.result,
            "critical": self.critical,
            "source_message_id": self.source_message_id,
            "source_sha256": self.source_sha256,
            "received_at": self.received_at,
            "receipt_id": self.receipt_id,
            "receipt_at": self.receipt_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Correction:
        return cls(**data)


@dataclass
class Conclusion:
    conclusion_id: str
    incident_id: str
    depends_on: tuple[str, ...]
    versions: list[ConclusionVersion] = field(default_factory=list)
    corrections: list[Correction] = field(default_factory=list)
    issued: bool = False
    issued_at: str | None = None
    issued_revision: int | None = None

    @property
    def revision(self) -> int:
        return self.versions[-1].revision

    @property
    def content(self) -> str:
        return self.versions[-1].content

    def to_dict(self) -> dict[str, Any]:
        return {
            "conclusion_id": self.conclusion_id,
            "incident_id": self.incident_id,
            "depends_on": list(self.depends_on),
            "versions": [v.to_dict() for v in self.versions],
            "corrections": [c.to_dict() for c in self.corrections],
            "issued": self.issued,
            "issued_at": self.issued_at,
            "issued_revision": self.issued_revision,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Conclusion:
        return cls(
            conclusion_id=data["conclusion_id"],
            incident_id=data["incident_id"],
            depends_on=tuple(data["depends_on"]),
            versions=[ConclusionVersion.from_dict(v) for v in data["versions"]],
            corrections=[Correction.from_dict(c) for c in data["corrections"]],
            issued=data["issued"],
            issued_at=data.get("issued_at"),
            issued_revision=data.get("issued_revision"),
        )


@dataclass(frozen=True)
class CustodyEvent:
    seq: int
    kind: str
    recorded_at: str
    message_id: str | None = None
    file_name: str | None = None
    sha256: str | None = None
    occurred_at: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "recorded_at": self.recorded_at,
            "message_id": self.message_id,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "occurred_at": self.occurred_at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CustodyEvent:
        return cls(**data)


@dataclass(frozen=True)
class HoldRecord:
    """文件名/消息编号关联冲突，暂停登记等待人工裁决。"""

    hold_id: str
    file_name: str
    message_id: str
    incoming_sha256: str
    existing_sha256: str
    reason: str
    held_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "file_name": self.file_name,
            "message_id": self.message_id,
            "incoming_sha256": self.incoming_sha256,
            "existing_sha256": self.existing_sha256,
            "reason": self.reason,
            "held_at": self.held_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HoldRecord:
        return cls(**data)


@dataclass(frozen=True)
class NotificationRecord:
    notification_id: str
    kind: str  # critical | critical_correction
    sample_id: str
    test: str
    event_seq: int | None
    dedupe_key: str
    sent_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "notification_id": self.notification_id,
            "kind": self.kind,
            "sample_id": self.sample_id,
            "test": self.test,
            "event_seq": self.event_seq,
            "dedupe_key": self.dedupe_key,
            "sent_at": self.sent_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NotificationRecord:
        return cls(**data)


@dataclass(frozen=True)
class SubmissionOutcome:
    kind: str  # applied | duplicate | held | quarantined | rejected
    message_id: str | None = None
    event_seq: int | None = None
    quarantine: QuarantineRecord | None = None
    hold: HoldRecord | None = None
    reason: str | None = None
    command: str | None = None

    @property
    def applied(self) -> bool:
        return self.kind == "applied"


class BusinessRuleError(ValueError):
    """命令通过了语法与模式校验，但违反保管链业务规则；状态不变。"""


# --------------------------------------------------------------------------
# 台账
# --------------------------------------------------------------------------


class ChainLedger:
    def __init__(
        self,
        *,
        store_path: str | Path | None = None,
        clock: Callable[[], str] | None = None,
        notifier: Callable[[NotificationRecord], None] | None = None,
    ) -> None:
        self.incidents: dict[str, dict[str, Any]] = {}
        self.samples: dict[str, Sample] = {}
        self.results: dict[tuple[str, str], ResultRecord] = {}
        self.conclusions: dict[str, Conclusion] = {}
        self.events: list[CustodyEvent] = []
        self.quarantines: list[QuarantineRecord] = []
        self.quarantine_by_hash: dict[str, QuarantineRecord] = {}
        self.holds: list[HoldRecord] = []
        self.notifications: list[NotificationRecord] = []
        # sha256 -> (message_id, event_seq)
        self.seen_hashes: dict[str, tuple[str, int]] = {}
        self.file_names: dict[str, str] = {}  # file_name -> sha256
        self.message_ids: dict[str, str] = {}  # message_id -> sha256
        self._seq = 0
        # 两阶段入账：_apply 期间产生的通知与回执先挂起，主事件入账后回填序号。
        self._pending_notifications: list[NotificationRecord] = []
        self._pending_receipts: list[dict[str, Any]] = []
        self._store_path = Path(store_path) if store_path else None
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self._notifier = notifier
        if self._store_path and self._store_path.exists():
            self.load()

    # ---- 公共入口 -------------------------------------------------------

    def submit_bytes(self, raw: bytes, file_name: str) -> SubmissionOutcome:
        """提交一个命令文件的原始字节，返回分类结果，绝不部分生效。"""
        digest = hashlib.sha256(raw).hexdigest()
        parsed = parse_document(raw)
        issues = list(parsed.issues)
        value: Any = None
        if parsed.ok:
            value = parsed.value
            issues = _sort_issues(
                issues + validate_command(value, parsed.key_spans), parsed.text
            )
        if issues:
            # 同一坏文件原样重送：稳定复用首次隔离记录，不重复堆积。
            existing = self.quarantine_by_hash.get(digest)
            if existing is not None:
                self._append(
                    "quarantine_repeated",
                    file_name=file_name,
                    sha256=digest,
                    detail={"quarantine_id": existing.quarantine_id},
                )
                self._save()
                return SubmissionOutcome(
                    kind="quarantined",
                    quarantine=existing,
                    reason=existing.primary_issue.code,
                )
            quarantine = make_quarantine(raw, file_name, issues)
            self.quarantines.append(quarantine)
            self.quarantine_by_hash[quarantine.sha256] = quarantine
            self._append(
                "quarantined",
                file_name=file_name,
                sha256=quarantine.sha256,
                detail={"codes": [i.code for i in issues]},
            )
            self._save()
            return SubmissionOutcome(
                kind="quarantined",
                quarantine=quarantine,
                reason=quarantine.primary_issue.code,
            )

        message_id: str = value["message_id"]
        command: str = value["command"]
        occurred_at: str = value["occurred_at"]
        payload: dict[str, Any] = value["payload"]

        # 1) 同一文件原样重送：幂等，返回首次登记位置。
        if digest in self.seen_hashes:
            first_message, first_seq = self.seen_hashes[digest]
            self._append(
                "duplicate_suppressed",
                message_id=message_id,
                file_name=file_name,
                sha256=digest,
                occurred_at=occurred_at,
                detail={"first_message_id": first_message, "first_event_seq": first_seq},
            )
            self._save()
            return SubmissionOutcome(
                kind="duplicate",
                message_id=first_message,
                event_seq=first_seq,
                command=command,
            )

        # 2) 文件名相同但内容不同：暂停关联。
        if file_name in self.file_names and self.file_names[file_name] != digest:
            hold = self._make_hold(
                file_name,
                message_id,
                digest,
                self.file_names[file_name],
                f"文件名 {file_name!r} 已关联不同内容，暂停新内容的关联登记",
            )
            self._save()
            return SubmissionOutcome(kind="held", hold=hold, reason=hold.reason)

        # 3) 消息编号复用但字节不同：同样暂停，防止顶替既有记录。
        if message_id in self.message_ids and self.message_ids[message_id] != digest:
            hold = self._make_hold(
                file_name,
                message_id,
                digest,
                self.message_ids[message_id],
                f"消息编号 {message_id!r} 曾对应不同字节，暂停登记",
            )
            self._save()
            return SubmissionOutcome(kind="held", hold=hold, reason=hold.reason)

        # 4) 业务应用；任何规则错误都不改变状态。
        try:
            detail = self._apply(command, payload, message_id, digest, occurred_at)
        except BusinessRuleError as exc:
            self._pending_notifications.clear()
            self._pending_receipts.clear()
            self._append(
                "rejected",
                message_id=message_id,
                file_name=file_name,
                sha256=digest,
                occurred_at=occurred_at,
                detail={"command": command, "reason": str(exc)},
            )
            self._save()
            return SubmissionOutcome(
                kind="rejected",
                message_id=message_id,
                command=command,
                reason=str(exc),
            )

        event = self._append(
            command,
            message_id=message_id,
            file_name=file_name,
            sha256=digest,
            occurred_at=occurred_at,
            detail={"command": command, **detail},
        )
        # 通知归属本条主命令事件：主事件先入账并回填序号；接收回执紧随其后。
        finalized_notes: list[NotificationRecord] = []
        if self._pending_notifications:
            for note in self._pending_notifications:
                finalized = replace(note, event_seq=event.seq)
                self.notifications[self.notifications.index(note)] = finalized
                finalized_notes.append(finalized)
            self._pending_notifications.clear()
        for receipt in self._pending_receipts:
            self._append("receipt", **receipt)
        self._pending_receipts.clear()
        self.seen_hashes[digest] = (message_id, event.seq)
        self.file_names[file_name] = digest
        self.message_ids[message_id] = digest
        # 先持久化（含通知去重键），再触发外部发送：崩溃在落盘前则整笔
        # 重放发送一次；落盘后重放绝不二发。持久化的通知记录即发件箱。
        self._save()
        for note in finalized_notes:
            if self._notifier is not None:
                self._notifier(note)
        return SubmissionOutcome(
            kind="applied",
            message_id=message_id,
            event_seq=event.seq,
            command=command,
        )

    def submit_path(self, path: str | Path) -> SubmissionOutcome:
        path = Path(path)
        return self.submit_bytes(path.read_bytes(), path.name)

    # ---- 命令应用 -------------------------------------------------------

    def _apply(
        self,
        command: str,
        payload: dict[str, Any],
        message_id: str,
        digest: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        if command == CMD_INTAKE:
            return self._do_intake(payload, message_id, digest, occurred_at)
        if command == CMD_SPLIT:
            return self._do_split(payload, message_id, digest, occurred_at)
        if command == CMD_CONSUME:
            return self._do_consume(payload, message_id, digest, occurred_at)
        if command == CMD_SUPPLEMENT:
            return self._do_supplement(payload, message_id, digest, occurred_at)
        if command == CMD_RESULT:
            return self._do_result(payload, message_id, digest, occurred_at)
        if command == CMD_CREATE_CONCLUSION:
            return self._do_create_conclusion(payload, message_id, digest, occurred_at)
        if command == CMD_REVISE_CONCLUSION:
            return self._do_revise_conclusion(payload, message_id, digest, occurred_at)
        if command == CMD_ISSUE_CONCLUSION:
            return self._do_issue_conclusion(payload, message_id, digest, occurred_at)
        raise BusinessRuleError(f"未知命令 {command!r}")  # 理论不可达

    def _require_incident(self, incident_id: str) -> dict[str, Any]:
        incident = self.incidents.get(incident_id)
        if incident is None:
            raise BusinessRuleError(f"误食事件 {incident_id!r} 尚未交接")
        return incident

    def _require_sample(self, sample_id: str) -> Sample:
        sample = self.samples.get(sample_id)
        if sample is None:
            raise BusinessRuleError(f"样本 {sample_id!r} 不存在")
        return sample

    def _do_intake(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        incident_id = payload["incident_id"]
        if incident_id in self.incidents:
            raise BusinessRuleError(f"事件 {incident_id!r} 已完成交接，不得重复登记")
        sample_ids = []
        total = 0
        for item in payload["samples"]:
            if item["sample_id"] in self.samples:
                raise BusinessRuleError(
                    f"样本编号 {item['sample_id']!r} 已在保管链中"
                )
        samples: list[Sample] = []
        for item in payload["samples"]:
            sample = Sample(
                sample_id=item["sample_id"],
                incident_id=incident_id,
                specimen=item["specimen"],
                tests=tuple(item["tests"]),
                initial_quantity=item["quantity"],
                quantity_remaining=item["quantity"],
                unit=item["unit"],
                root_sample_id=item["sample_id"],
                origin="intake",
            )
            samples.append(sample)
            sample_ids.append(sample.sample_id)
            total += sample.initial_quantity
        self.incidents[incident_id] = {
            "incident_id": incident_id,
            "created_at": occurred_at,
            "source_message_id": message_id,
        }
        for sample in samples:
            self.samples[sample.sample_id] = sample
        return {
            "incident_id": incident_id,
            "sample_ids": sample_ids,
            "total_quantity": total,
        }

    def _do_split(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        parent = self._require_sample(payload["parent_sample_id"])
        children = payload["children"]
        allocated = sum(child["quantity"] for child in children)
        remaining = payload["remaining_quantity"]
        if allocated + remaining != parent.quantity_remaining:
            raise BusinessRuleError(
                f"分样数量不守恒：父样现有 {parent.quantity_remaining} "
                f"{parent.unit}，子样合计 {allocated}，申报剩余 {remaining}，"
                f"差额 {parent.quantity_remaining - allocated - remaining}"
            )
        for child in children:
            if child["sample_id"] in self.samples:
                raise BusinessRuleError(
                    f"子样编号 {child['sample_id']!r} 已在保管链中"
                )
        child_ids = []
        for child in children:
            child_tests = tuple(child.get("tests") or parent.tests)
            unknown = [t for t in child_tests if t not in parent.tests]
            if unknown:
                raise BusinessRuleError(
                    f"子样 {child['sample_id']!r} 申报的项目 {unknown} "
                    f"不属于父样 {parent.sample_id!r} 的联检项目 {list(parent.tests)}"
                )
            sample = Sample(
                sample_id=child["sample_id"],
                incident_id=parent.incident_id,
                specimen=parent.specimen,
                tests=child_tests,
                initial_quantity=child["quantity"],
                quantity_remaining=child["quantity"],
                unit=parent.unit,
                parent_sample_id=parent.sample_id,
                root_sample_id=parent.root_sample_id,
                origin="split",
            )
            self.samples[sample.sample_id] = sample
            parent.children.append(sample.sample_id)
            child_ids.append(sample.sample_id)
        parent.quantity_remaining = remaining
        return {
            "parent_sample_id": parent.sample_id,
            "child_sample_ids": child_ids,
            "allocated": allocated,
            "remaining_quantity": remaining,
        }

    def _do_consume(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        sample = self._require_sample(payload["sample_id"])
        test = payload["test"]
        qty = payload["quantity"]
        if test not in sample.tests:
            raise BusinessRuleError(
                f"样本 {sample.sample_id!r} 的联检项目不含 {test!r}"
            )
        if test in sample.consumed_for:
            raise BusinessRuleError(
                f"样本 {sample.sample_id!r} 的 {test} 已耗用 "
                f"{sample.consumed_for[test]} {sample.unit}，复测必须先补样"
            )
        if qty > sample.quantity_remaining:
            raise BusinessRuleError(
                f"耗用超量：请求 {qty} {sample.unit}，仅剩 "
                f"{sample.quantity_remaining} {sample.unit}"
            )
        sample.quantity_remaining -= qty
        sample.consumed_for[test] = qty
        return {
            "sample_id": sample.sample_id,
            "test": test,
            "consumed_quantity": qty,
            "remaining_quantity": sample.quantity_remaining,
        }

    def _do_supplement(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        self._require_incident(payload["incident_id"])
        sample_id = payload["sample_id"]
        if sample_id in self.samples:
            raise BusinessRuleError(f"补样编号 {sample_id!r} 已在保管链中")
        sample = Sample(
            sample_id=sample_id,
            incident_id=payload["incident_id"],
            specimen=payload["specimen"],
            tests=tuple(payload["tests"]),
            initial_quantity=payload["quantity"],
            quantity_remaining=payload["quantity"],
            unit=payload["unit"],
            root_sample_id=sample_id,
            origin="supplement",
        )
        self.samples[sample_id] = sample
        return {
            "incident_id": sample.incident_id,
            "sample_id": sample_id,
            "reason": payload["reason"],
            "quantity": sample.initial_quantity,
        }

    def _do_result(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        sample = self._require_sample(payload["sample_id"])
        test = payload["test"]
        if test not in sample.tests:
            raise BusinessRuleError(
                f"样本 {sample.sample_id!r} 的联检项目不含 {test!r}"
            )
        if test not in sample.consumed_for:
            raise BusinessRuleError(
                f"样本 {sample.sample_id!r} 的 {test} 尚未登记耗用，不能接收结果"
            )
        key = (sample.sample_id, test)
        previous = self.results.get(key)
        version = 1 if previous is None else previous.version + 1
        record = ResultRecord(
            sample_id=sample.sample_id,
            test=test,
            analyte=payload["analyte"],
            result=payload["result"],
            critical=payload["critical"],
            version=version,
            source_message_id=message_id,
            source_sha256=digest,
            recorded_at=occurred_at,
        )
        self.results[key] = record

        notifications: list[str] = []
        # 危急通知绑定事件序号；同版本重放被幂等挡在入口，不会走到这里。
        if payload["critical"]:
            note = self._notify(
                kind="critical" if version == 1 else "critical_correction",
                sample=sample,
                test=test,
                dedupe_key=f"{sample.sample_id}:{test}:v{version}",
            )
            notifications.append(note.notification_id)
        updated, corrected = self._route_late_result(sample, record, message_id, digest)
        return {
            "sample_id": sample.sample_id,
            "test": test,
            "version": version,
            "critical": payload["critical"],
            "notification_ids": notifications,
            "updated_conclusions": updated,
            "corrected_conclusions": corrected,
        }

    def _route_late_result(
        self,
        sample: Sample,
        record: ResultRecord,
        message_id: str,
        digest: str,
    ) -> tuple[list[str], list[str]]:
        updated: list[str] = []
        corrected: list[str] = []
        for conclusion in self.conclusions.values():
            if conclusion.incident_id != sample.incident_id:
                continue
            if record.test not in conclusion.depends_on:
                continue
            if not conclusion.issued:
                # 仅更新依赖它的未签发结论：形成新版本，旧版本仍可审计。
                content = (
                    f"{conclusion.content}\n[结果更新 v{record.version} "
                    f"{record.test}/{record.analyte}={record.result}"
                    f"（样本 {sample.sample_id}，来源 {message_id}）]"
                )
                version = ConclusionVersion(
                    revision=conclusion.revision + 1,
                    kind="result_update",
                    content=content,
                    recorded_at=record.recorded_at,
                    source_message_id=message_id,
                    source_sha256=digest,
                    results=conclusion.versions[-1].results
                    + (f"{sample.sample_id}:{record.test}#v{record.version}",),
                )
                conclusion.versions.append(version)
                updated.append(conclusion.conclusion_id)
            else:
                # 已签发版本不可变：只追加更正与接收回执。
                n = len(conclusion.corrections) + 1
                now = self._clock()
                correction = Correction(
                    correction_id=(
                        f"cor-{conclusion.conclusion_id}-{n}"
                    ),
                    sample_id=sample.sample_id,
                    test=record.test,
                    analyte=record.analyte,
                    result=record.result,
                    critical=record.critical,
                    source_message_id=message_id,
                    source_sha256=digest,
                    received_at=now,
                    receipt_id=f"ack-{conclusion.conclusion_id}-{n}",
                    receipt_at=now,
                )
                conclusion.corrections.append(correction)
                # 回执事件在主命令事件之后入账，序号由提交主流程追加。
                self._pending_receipts.append(
                    {
                        "message_id": message_id,
                        "sha256": digest,
                        "occurred_at": record.recorded_at,
                        "detail": {
                            "conclusion_id": conclusion.conclusion_id,
                            "issued_revision": conclusion.issued_revision,
                            "correction_id": correction.correction_id,
                            "receipt_id": correction.receipt_id,
                        },
                    }
                )
                corrected.append(conclusion.conclusion_id)
        return updated, corrected

    def _snapshot_results(
        self, incident_id: str, depends_on: Iterable[str]
    ) -> tuple[str, ...]:
        refs: list[str] = []
        wanted = set(depends_on)
        for (sample_id, test), record in self.results.items():
            sample = self.samples.get(sample_id)
            if sample is not None and sample.incident_id == incident_id and test in wanted:
                refs.append(f"{sample_id}:{test}#v{record.version}")
        return tuple(sorted(refs))

    def _do_create_conclusion(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        incident_id = payload["incident_id"]
        self._require_incident(incident_id)
        conclusion_id = payload["conclusion_id"]
        if conclusion_id in self.conclusions:
            raise BusinessRuleError(f"结论 {conclusion_id!r} 已存在")
        depends_on = tuple(payload["depends_on"])
        unknown = [t for t in depends_on if t not in PANEL_TESTS]
        if unknown:
            raise BusinessRuleError(f"结论依赖未知联检项目 {unknown}")
        conclusion = Conclusion(
            conclusion_id=conclusion_id,
            incident_id=incident_id,
            depends_on=depends_on,
        )
        conclusion.versions.append(
            ConclusionVersion(
                revision=1,
                kind="create",
                content=payload["content"],
                recorded_at=occurred_at,
                source_message_id=message_id,
                source_sha256=digest,
                results=self._snapshot_results(incident_id, depends_on),
            )
        )
        self.conclusions[conclusion_id] = conclusion
        return {
            "incident_id": incident_id,
            "conclusion_id": conclusion_id,
            "depends_on": list(depends_on),
            "revision": 1,
        }

    def _do_revise_conclusion(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        conclusion = self.conclusions.get(payload["conclusion_id"])
        if conclusion is None:
            raise BusinessRuleError(f"结论 {payload['conclusion_id']!r} 不存在")
        if conclusion.incident_id != payload["incident_id"]:
            raise BusinessRuleError("结论与事件编号不匹配")
        if conclusion.issued:
            raise BusinessRuleError(
                f"结论 {conclusion.conclusion_id!r} 已签发第 "
                f"{conclusion.issued_revision} 版，不能直接修订；"
                "晚到结果只能以更正附记追加"
            )
        conclusion.versions.append(
            ConclusionVersion(
                revision=conclusion.revision + 1,
                kind="revise",
                content=payload["content"],
                recorded_at=occurred_at,
                source_message_id=message_id,
                source_sha256=digest,
                results=conclusion.versions[-1].results,
            )
        )
        return {
            "conclusion_id": conclusion.conclusion_id,
            "revision": conclusion.revision,
        }

    def _do_issue_conclusion(
        self, payload: dict[str, Any], message_id: str, digest: str, occurred_at: str
    ) -> dict[str, Any]:
        conclusion = self.conclusions.get(payload["conclusion_id"])
        if conclusion is None:
            raise BusinessRuleError(f"结论 {payload['conclusion_id']!r} 不存在")
        if conclusion.incident_id != payload["incident_id"]:
            raise BusinessRuleError("结论与事件编号不匹配")
        if conclusion.issued:
            raise BusinessRuleError(
                f"结论 {conclusion.conclusion_id!r} 已签发，不能重复签发"
            )
        conclusion.issued = True
        conclusion.issued_at = occurred_at
        conclusion.issued_revision = conclusion.revision
        return {
            "conclusion_id": conclusion.conclusion_id,
            "issued_revision": conclusion.issued_revision,
        }

    # ---- 通知、暂停、事件 ----------------------------------------------

    def _notify(self, *, kind: str, sample: Sample, test: str, dedupe_key: str):
        existing = next(
            (n for n in self.notifications if n.dedupe_key == dedupe_key), None
        )
        if existing is not None:
            # 双重保险：即便上层重放，同一去重键绝不二发。
            return existing
        note = NotificationRecord(
            notification_id=f"note-{len(self.notifications) + 1}",
            kind=kind,
            sample_id=sample.sample_id,
            test=test,
            event_seq=None,  # 主命令事件入账后由提交主流程回填
            dedupe_key=dedupe_key,
            sent_at=self._clock(),
        )
        self.notifications.append(note)
        self._pending_notifications.append(note)
        return note

    def _make_hold(
        self,
        file_name: str,
        message_id: str,
        incoming: str,
        existing: str,
        reason: str,
    ) -> HoldRecord:
        hold = HoldRecord(
            hold_id=f"hold-{len(self.holds) + 1}",
            file_name=file_name,
            message_id=message_id,
            incoming_sha256=incoming,
            existing_sha256=existing,
            reason=reason,
            held_at=self._clock(),
        )
        self.holds.append(hold)
        self._append(
            "held",
            message_id=message_id,
            file_name=file_name,
            sha256=incoming,
            detail={"reason": reason, "existing_sha256": existing},
        )
        return hold

    def _append(self, kind: str, **kwargs: Any) -> CustodyEvent:
        self._seq += 1
        event = CustodyEvent(seq=self._seq, recorded_at=self._clock(), kind=kind, **kwargs)
        self.events.append(event)
        return event

    # ---- 守恒核查 -------------------------------------------------------

    def mass_balance(self, root_sample_id: str) -> dict[str, int]:
        """返回分样树质量平衡：初始量、剩余量合计、耗用量合计及差额。"""
        root = self._require_sample(root_sample_id)
        remaining = 0
        consumed = 0
        stack = [root.sample_id]
        seen: set[str] = set()
        while stack:
            node_id = stack.pop()
            if node_id in seen:
                raise BusinessRuleError(f"分样树出现环：{node_id}")
            seen.add(node_id)
            node = self.samples[node_id]
            remaining += node.quantity_remaining
            consumed += sum(node.consumed_for.values())
            stack.extend(node.children)
        return {
            "root_sample_id": root.sample_id,
            "initial_quantity": root.initial_quantity,
            "remaining_total": remaining,
            "consumed_total": consumed,
            "difference": root.initial_quantity - remaining - consumed,
        }

    def assert_balanced(self) -> None:
        """对每棵分样树断言质量平衡，供测试与恢复后巡检使用。"""
        roots = [
            s.sample_id
            for s in self.samples.values()
            if s.parent_sample_id is None
        ]
        for root_id in roots:
            report = self.mass_balance(root_id)
            if report["difference"] != 0:
                raise BusinessRuleError(
                    f"分样树 {root_id} 数量失衡：{report}"
                )

    # ---- 持久化 ---------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "seq": self._seq,
            "incidents": self.incidents,
            "samples": {sid: s.to_dict() for sid, s in self.samples.items()},
            "results": {
                f"{sid}\x00{test}": r.to_dict()
                for (sid, test), r in self.results.items()
            },
            "conclusions": {
                cid: c.to_dict() for cid, c in self.conclusions.items()
            },
            "events": [e.to_dict() for e in self.events],
            "quarantines": [q.to_dict() for q in self.quarantines],
            "holds": [h.to_dict() for h in self.holds],
            "notifications": [n.to_dict() for n in self.notifications],
            "seen_hashes": [
                {"sha256": digest, "message_id": mid, "event_seq": seq}
                for digest, (mid, seq) in self.seen_hashes.items()
            ],
            "file_names": self.file_names,
            "message_ids": self.message_ids,
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        self._seq = data["seq"]
        self.incidents = dict(data["incidents"])
        self.samples = {
            sid: Sample.from_dict(item) for sid, item in data["samples"].items()
        }
        self.results = {}
        for compound, item in data["results"].items():
            record = ResultRecord.from_dict(item)
            self.results[record.key()] = record
        self.conclusions = {
            cid: Conclusion.from_dict(item)
            for cid, item in data["conclusions"].items()
        }
        self.events = [CustodyEvent.from_dict(item) for item in data["events"]]
        self.quarantines = [
            QuarantineRecord.from_dict(item) for item in data["quarantines"]
        ]
        self.quarantine_by_hash = {
            q.sha256: q for q in self.quarantines
        }
        self.holds = [HoldRecord.from_dict(item) for item in data["holds"]]
        self.notifications = [
            NotificationRecord.from_dict(item) for item in data["notifications"]
        ]
        self.seen_hashes = {
            item["sha256"]: (item["message_id"], item["event_seq"])
            for item in data["seen_hashes"]
        }
        self.file_names = dict(data["file_names"])
        self.message_ids = dict(data["message_ids"])

    def save(self) -> None:
        if self._store_path is None:
            return
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True
        )
        fd, tmp_name = tempfile.mkstemp(
            prefix=".ledger-", suffix=".tmp", dir=str(self._store_path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._store_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _save(self) -> None:
        self.save()

    def load(self) -> None:
        data = json.loads(self._store_path.read_text(encoding="utf-8"))
        self.load_dict(data)


__all__ = [
    "BusinessRuleError",
    "ChainLedger",
    "Conclusion",
    "ConclusionVersion",
    "Correction",
    "CustodyEvent",
    "HoldRecord",
    "NotificationRecord",
    "ResultRecord",
    "Sample",
    "SubmissionOutcome",
]
