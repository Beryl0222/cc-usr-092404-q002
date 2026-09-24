"""证据入口：原始字节在形成领域记录之前必须通过严格解析与模式校验。

任何下列情况都会在进入领域台账之前被稳定拒绝，并形成隔离记录
（:class:`QuarantineRecord`），保留原始字节 SHA-256 摘要与全部问题位置：

* 非 UTF-8（无 BOM）编码、空文档、JSON 语法错误；
* 同一对象内出现重复键（标准 ``json`` 会静默取后值，本模块逐个记录）；
* 顶层值之后存在尾随内容（包含两个拼接对象的“混合文件”）；
* 未知字段、必填字段缺失、字段类型不符；
* ``occurred_at`` 不是带时区偏移的合法 ISO-8601 时间；
* 编号/来源为空、修订号越界、``schema_version`` 不受支持。

定位信息同时给出 1 起始的行列号、字符偏移与原始字节偏移，行列以
``\\n`` 分行，可直接回到原文件复核。

模块分两层：

* :func:`parse_document` 只做字节解码与 JSON 语法（含重复键、尾随内容）；
* :func:`validate_fields` 按声明式字段规范做模式校验。

:class:`EvidenceIngress` 把两层组合为最小交接信封合同；保管链台账对业务
命令文件复用同样两层，只是换用业务字段规范。
"""

from __future__ import annotations

import hashlib
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .contracts import DomainRecord

# 当前支持的 schema_version；新版本必须先声明迁移方式才能进入入口。
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})
REQUIRED_FIELDS = (
    "schema_version",
    "record_id",
    "domain",
    "occurred_at",
    "revision",
    "source",
)
# 隔离记录中为人工辨认保留的原始字节前缀长度。
EXCERPT_LIMIT = 200
_BOM_PREFIXES = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00")


class _FatalParse(Exception):
    """不可恢复的语法错误，携带字符偏移。"""

    def __init__(self, offset: int, message: str) -> None:
        super().__init__(message)
        self.offset = offset
        self.message = message


@dataclass(frozen=True)
class Issue:
    """一条可定位的入口问题。"""

    code: str
    message: str
    line: int | None = None
    column: int | None = None
    char_offset: int | None = None
    byte_offset: int | None = None
    path: str | None = None

    def location(self) -> str:
        if self.line is not None and self.column is not None:
            base = f"第 {self.line} 行第 {self.column} 列"
            if self.byte_offset is not None:
                base += f"（字节偏移 {self.byte_offset}）"
            return base
        if self.byte_offset is not None:
            return f"字节偏移 {self.byte_offset}"
        return "位置未知"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "char_offset": self.char_offset,
            "byte_offset": self.byte_offset,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Issue":
        return cls(
            code=data["code"],
            message=data["message"],
            line=data.get("line"),
            column=data.get("column"),
            char_offset=data.get("char_offset"),
            byte_offset=data.get("byte_offset"),
            path=data.get("path"),
        )


@dataclass(frozen=True)
class QuarantineRecord:
    """被隔离的原始提交：字节摘要与问题位置随记录长期保留。"""

    quarantine_id: str
    file_name: str
    sha256: str
    byte_length: int
    issues: tuple[Issue, ...]
    received_at: str
    raw_excerpt: bytes = b""

    @property
    def primary_issue(self) -> Issue:
        return self.issues[0]

    def to_dict(self) -> dict[str, Any]:
        import base64

        return {
            "quarantine_id": self.quarantine_id,
            "file_name": self.file_name,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "received_at": self.received_at,
            "raw_excerpt_b64": base64.b64encode(self.raw_excerpt).decode("ascii"),
            "issues": [issue.to_dict() for issue in self.issues],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QuarantineRecord":
        import base64

        if "raw_excerpt_b64" in data:
            excerpt = base64.b64decode(data["raw_excerpt_b64"])
        else:
            excerpt = data.get("raw_excerpt", "").encode("utf-8", errors="replace")
        return cls(
            quarantine_id=data["quarantine_id"],
            file_name=data["file_name"],
            sha256=data["sha256"],
            byte_length=data["byte_length"],
            issues=tuple(Issue.from_dict(item) for item in data["issues"]),
            received_at=data["received_at"],
            raw_excerpt=excerpt,
        )


class EvidenceRejected(ValueError):
    """严格入口拒绝加载时抛出，携带完整隔离记录。"""

    def __init__(self, quarantine: QuarantineRecord) -> None:
        head = quarantine.primary_issue
        super().__init__(
            f"证据入口拒绝 {quarantine.file_name}：{head.code} @ {head.location()}，"
            f"共 {len(quarantine.issues)} 项问题（隔离号 {quarantine.quarantine_id}）"
        )
        self.quarantine = quarantine


@dataclass(frozen=True)
class IngressResult:
    """单次提交结果：record 与 quarantine 恰有一个非空。"""

    ok: bool
    record: DomainRecord | None
    quarantine: QuarantineRecord | None

    def unwrap(self) -> DomainRecord:
        if self.record is None:
            raise EvidenceRejected(self.quarantine)  # type: ignore[arg-type]
        return self.record


@dataclass(frozen=True)
class ParsedDocument:
    """字节 -> 语法层结果。value 仅在无致命语法错误时可用。"""

    ok: bool
    value: Any
    issues: tuple[Issue, ...]
    text: str
    key_spans: tuple[tuple[str, int, str], ...]


# --------------------------------------------------------------------------
# 定位工具
# --------------------------------------------------------------------------

def _line_starts(text: str) -> list[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def _line_column(starts: list[int], offset: int) -> tuple[int, int]:
    line_idx = max(0, bisect_right(starts, offset) - 1)
    return line_idx + 1, offset - starts[line_idx] + 1


def _byte_line_column(raw: bytes, offset: int) -> tuple[int, int]:
    line = raw.count(b"\n", 0, offset) + 1
    last_nl = raw.rfind(b"\n", 0, offset)
    column = offset - last_nl  # last_nl == -1 时 column == offset + 1
    return line, column


# --------------------------------------------------------------------------
# 语法层解析
# --------------------------------------------------------------------------

class _Parser:
    """手写递归下降解析器：重复键收集为问题，语法错误带偏移中止。"""

    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)
        self.i = 0
        self.starts = _line_starts(text)
        self.issues: list[Issue] = []
        # (JSON 指针路径, 键首字符偏移, 键名)
        self.key_spans: list[tuple[str, int, str]] = []

    def parse(self) -> Any:
        self._skip_ws()
        if self.i >= self.n:
            raise _FatalParse(self.i, "文档为空，没有任何 JSON 值")
        value = self._parse_value("")
        self._skip_ws()
        if self.i < self.n:
            # 典型场景：两个对象拼接的混合文件，或 NDJSON 被当作单对象提交。
            self.issues.append(
                Issue(
                    code="trailing_content",
                    message="顶层 JSON 值之后存在未被允许的尾随内容",
                    char_offset=self.i,
                )
            )
        return value

    def _skip_ws(self) -> None:
        while self.i < self.n and self.s[self.i] in " \t\n\r":
            self.i += 1

    def _expect(self, ch: str, what: str) -> None:
        if self.i >= self.n or self.s[self.i] != ch:
            raise _FatalParse(self.i, f"应当出现 {what}")
        self.i += 1

    def _parse_value(self, path: str) -> Any:
        if self.i >= self.n:
            raise _FatalParse(self.i, "文档在期望值的位置结束")
        ch = self.s[self.i]
        if ch == '"':
            return self._parse_string()
        if ch == "{":
            return self._parse_object(path)
        if ch == "[":
            return self._parse_array(path)
        if ch == "-" or ch.isdigit():
            return self._parse_number()
        for literal, value in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(literal, self.i):
                self.i += len(literal)
                return value
        raise _FatalParse(self.i, f"无法识别的 JSON 值起始字符 {ch!r}")

    def _parse_string(self) -> str:
        start = self.i
        self.i += 1  # 开引号
        out: list[str] = []
        escapes = {
            '"': '"',
            "\\": "\\",
            "/": "/",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }
        while True:
            if self.i >= self.n:
                raise _FatalParse(start, "字符串缺少闭合引号")
            ch = self.s[self.i]
            if ch == '"':
                self.i += 1
                return "".join(out)
            if ch == "\n":
                raise _FatalParse(self.i, "字符串中不允许出现未转义的换行")
            if ord(ch) < 0x20:
                raise _FatalParse(self.i, "字符串中不允许出现未转义的控制字符")
            if ch != "\\":
                out.append(ch)
                self.i += 1
                continue
            esc_at = self.i
            self.i += 1
            if self.i >= self.n:
                raise _FatalParse(esc_at, "转义序列在文档结束处中断")
            marker = self.s[self.i]
            if marker in escapes:
                out.append(escapes[marker])
                self.i += 1
            elif marker == "u":
                out.append(self._parse_unicode_escape(esc_at))
            else:
                raise _FatalParse(self.i, f"非法转义序列 \\{marker}")

    def _parse_unicode_escape(self, esc_at: int) -> str:
        def hex4(at: int) -> int:
            chunk = self.s[at : at + 4]
            if len(chunk) < 4 or any(c not in "0123456789abcdefABCDEF" for c in chunk):
                raise _FatalParse(at, "\\u 转义后必须紧跟 4 位十六进制数字")
            return int(chunk, 16)

        self.i += 1  # 跳过 u
        hi_at = self.i
        high = hex4(hi_at)
        self.i += 4
        if 0xD800 <= high <= 0xDBFF:
            if self.s.startswith("\\u", self.i):
                low_at = self.i + 2
                low = hex4(low_at)
                if 0xDC00 <= low <= 0xDFFF:
                    self.i = low_at + 4
                    return chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
            raise _FatalParse(esc_at, "高代理项之后缺少匹配的低代理项")
        if 0xDC00 <= high <= 0xDFFF:
            raise _FatalParse(esc_at, "出现未配对的低代理项")
        return chr(high)

    def _parse_number(self) -> int | float:
        start = self.i
        if self.s[self.i] == "-":
            self.i += 1
        if self.i >= self.n:
            raise _FatalParse(start, "负号之后缺少数字")
        if self.s[self.i] == "0":
            self.i += 1
        elif self.s[self.i].isdigit():
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
        else:
            raise _FatalParse(self.i, "数字的整数部分缺失或含有前导零")
        is_float = False
        if self.i < self.n and self.s[self.i] == ".":
            is_float = True
            dot = self.i
            self.i += 1
            frac_start = self.i
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
            if self.i == frac_start:
                raise _FatalParse(dot, "小数点之后必须至少有一位数字")
        if self.i < self.n and self.s[self.i] in "eE":
            is_float = True
            exp_at = self.i
            self.i += 1
            if self.i < self.n and self.s[self.i] in "+-":
                self.i += 1
            digits_start = self.i
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
            if self.i == digits_start:
                raise _FatalParse(exp_at, "指数部分必须至少有一位数字")
        token = self.s[start : self.i]
        return float(token) if is_float else int(token)

    def _parse_object(self, path: str) -> dict[str, Any]:
        self.i += 1  # {
        result: dict[str, Any] = {}
        first_seen: dict[str, int] = {}
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return result
        while True:
            self._skip_ws()
            if self.i >= self.n:
                raise _FatalParse(self.i, "对象缺少闭合 }")
            if self.s[self.i] != '"':
                raise _FatalParse(self.i, "对象键必须是双引号字符串")
            key_at = self.i
            key = self._parse_string()
            self.key_spans.append((path, key_at, key))
            self._skip_ws()
            self._expect(":", "冒号 ':'")
            self._skip_ws()
            child_path = f"{path}/{key}"
            if key in first_seen:
                line, column = _line_column(self.starts, key_at)
                first_line, first_col = _line_column(self.starts, first_seen[key])
                self.issues.append(
                    Issue(
                        code="duplicate_key",
                        message=(
                            f"重复键 {key!r}：首次出现于第 {first_line} 行第 "
                            f"{first_col} 列，标准加载器会静默取后值，此处予以拒绝"
                        ),
                        line=line,
                        column=column,
                        char_offset=key_at,
                        path=child_path,
                    )
                )
            else:
                first_seen[key] = key_at
            result[key] = self._parse_value(child_path)
            self._skip_ws()
            if self.i >= self.n:
                raise _FatalParse(self.i, "对象缺少闭合 }")
            if self.s[self.i] == ",":
                self.i += 1
                continue
            if self.s[self.i] == "}":
                self.i += 1
                return result
            raise _FatalParse(self.i, "对象成员之间必须使用逗号 ','")

    def _parse_array(self, path: str) -> list[Any]:
        self.i += 1  # [
        items: list[Any] = []
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return items
        idx = 0
        while True:
            self._skip_ws()
            items.append(self._parse_value(f"{path}/{idx}"))
            idx += 1
            self._skip_ws()
            if self.i >= self.n:
                raise _FatalParse(self.i, "数组缺少闭合 ]")
            if self.s[self.i] == ",":
                self.i += 1
                continue
            if self.s[self.i] == "]":
                self.i += 1
                return items
            raise _FatalParse(self.i, "数组元素之间必须使用逗号 ','")


def parse_document(raw: bytes) -> ParsedDocument:
    """字节 -> 语法层：编码、重复键、尾随内容在此拦截。"""
    if raw.startswith(_BOM_PREFIXES):
        issue = Issue(
            code="encoding",
            message="仅接受无 BOM 的 UTF-8 文件，检测到 BOM 或非 UTF-8 字节序",
            line=1,
            column=1,
            byte_offset=0,
        )
        return ParsedDocument(False, None, (issue,), "", ())

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        line, column = _byte_line_column(raw, exc.start)
        issue = Issue(
            code="encoding",
            message=f"文件不是合法 UTF-8：{exc.reason}",
            line=line,
            column=column,
            byte_offset=exc.start,
        )
        return ParsedDocument(False, None, (issue,), "", ())

    parser = _Parser(text)
    issues: list[Issue]
    try:
        value = parser.parse()
    except _FatalParse as exc:
        line, column = _line_column(parser.starts, exc.offset)
        fatal = Issue(
            code="syntax",
            message=exc.message,
            line=line,
            column=column,
            char_offset=exc.offset,
            byte_offset=len(text[: exc.offset].encode("utf-8")),
        )
        issues = [fatal, *parser.issues]
        value = None
        ok = False
    else:
        issues = list(parser.issues)
        ok = not issues
    return ParsedDocument(
        ok=ok,
        value=value,
        issues=tuple(_sort_issues(issues, text)),
        text=text,
        key_spans=tuple(parser.key_spans),
    )


# --------------------------------------------------------------------------
# 模式层
# --------------------------------------------------------------------------

# 字段规范：类型，或 (类型, 额外校验函数)。
# 额外校验返回 None 表示通过；返回 str 时问题码为 invalid_value；
# 返回 (code, message) 时使用指定问题码（如 invalid_time）。
FieldSpec = tuple[
    type, Callable[[Any], "str | tuple[str, str] | None"] | None
]


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def enum_check(allowed: tuple[Any, ...]) -> Callable[[Any], str | None]:
    def check(value: Any) -> str | None:
        if value not in allowed:
            return f"取值必须是 {list(allowed)} 之一，实际为 {value!r}"
        return None

    return check


def non_empty_str(value: Any) -> str | None:
    if isinstance(value, str) and value.strip() == "":
        return "不允许为空字符串"
    return None


def positive_int(value: Any) -> str | None:
    if value < 1:
        return f"必须为正整数，实际为 {value}"
    return None


def iso_time(value: Any) -> tuple[str, str] | None:
    # 跨机构交接统一要求 ISO-8601 的 'T' 分隔形式；Python 3.11 的
    # fromisoformat 宽容接受空格分隔，这里显式收紧。
    if "T" not in value:
        return "invalid_time", f"必须使用 'T' 分隔日期与时间：{value!r}"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return "invalid_time", f"不是合法 ISO-8601 时间：{value!r}"
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return (
            "invalid_time",
            f"必须携带时区偏移，避免跨机构解读歧义：{value!r}",
        )
    return None


def validate_fields(
    value: Any,
    key_spans: tuple[tuple[str, int, str], ...],
    fields: dict[str, FieldSpec],
    required: tuple[str, ...],
    *,
    pointer: str = "",
) -> list[Issue]:
    """按声明式规范校验对象；未知字段、缺失、类型、取值问题全部收集。"""
    issues: list[Issue] = []
    if not isinstance(value, dict):
        issues.append(
            Issue(
                code="not_object",
                message=f"顶层必须是 JSON 对象，实际为 {type(value).__name__}",
                line=1,
                column=1,
                char_offset=0,
                path=pointer or "/",
            )
        )
        return issues

    span_by_path: dict[str, int] = {}
    for path, offset, key in key_spans:
        span_by_path[f"{path}/{key}"] = offset

    for name in required:
        if name not in value:
            issues.append(
                Issue(
                    code="missing_field",
                    message=f"缺少必填字段 {name!r}",
                    path=f"{pointer}/{name}",
                )
            )
    for name, item in value.items():
        path = f"{pointer}/{name}"
        offset = span_by_path.get(path)
        if name not in fields:
            issues.append(
                Issue(
                    code="unknown_field",
                    message=f"未知字段 {name!r}，当前合同仅接受 {sorted(fields)}",
                    char_offset=offset,
                    path=path,
                )
            )
            continue
        expected_type, extra = fields[name]
        if expected_type is int:
            type_ok = _is_int(item)
        else:
            type_ok = isinstance(item, expected_type)
        if not type_ok:
            issues.append(
                Issue(
                    code="invalid_type",
                    message=(
                        f"字段 {name!r} 类型应为 {expected_type.__name__}，"
                        f"实际为 {type(item).__name__}"
                    ),
                    char_offset=offset,
                    path=path,
                )
            )
            continue
        if extra is not None:
            found = extra(item)
            if found:
                code, message = (
                    found if isinstance(found, tuple) else ("invalid_value", found)
                )
                issues.append(
                    Issue(
                        code=code,
                        message=f"字段 {name!r} {message}",
                        char_offset=offset,
                        path=path,
                    )
                )
    return issues


def _sort_issues(issues: list[Issue], text: str) -> list[Issue]:
    """按文档位置稳定排序，并为仅有字符偏移的问题补齐行列与字节偏移。"""
    starts = _line_starts(text)

    def rank(issue: Issue) -> tuple[int, int, str]:
        off = issue.char_offset
        if off is None:
            return (1, 0, issue.code + (issue.path or ""))
        return (0, off, issue.code)

    result: list[Issue] = []
    for issue in sorted(issues, key=rank):
        if issue.char_offset is not None and (
            issue.line is None or issue.byte_offset is None
        ):
            line, column = _line_column(starts, issue.char_offset)
            issue = Issue(
                code=issue.code,
                message=issue.message,
                line=issue.line if issue.line is not None else line,
                column=issue.column if issue.column is not None else column,
                char_offset=issue.char_offset,
                byte_offset=issue.byte_offset
                if issue.byte_offset is not None
                else len(text[: issue.char_offset].encode("utf-8")),
                path=issue.path,
            )
        result.append(issue)
    return result


def make_quarantine(
    raw: bytes,
    file_name: str,
    issues: list[Issue] | tuple[Issue, ...],
    *,
    received_at: str | None = None,
) -> QuarantineRecord:
    digest = hashlib.sha256(raw).hexdigest()
    return QuarantineRecord(
        quarantine_id=f"q-{digest[:12]}",
        file_name=file_name,
        sha256=digest,
        byte_length=len(raw),
        issues=tuple(issues),
        received_at=received_at or datetime.now(timezone.utc).isoformat(),
        raw_excerpt=raw[:EXCERPT_LIMIT],
    )


# --------------------------------------------------------------------------
# 最小交接信封入口
# --------------------------------------------------------------------------

_ENVELOPE_FIELDS: dict[str, FieldSpec] = {
    "schema_version": (
        int,
        lambda v: None
        if v in SUPPORTED_SCHEMA_VERSIONS
        else f"schema_version={v} 不受支持，当前接受 {sorted(SUPPORTED_SCHEMA_VERSIONS)}",
    ),
    "record_id": (str, non_empty_str),
    "domain": (str, non_empty_str),
    "occurred_at": (str, iso_time),
    "revision": (int, positive_int),
    "source": (str, non_empty_str),
}


class EvidenceIngress:
    """最小交接信封的严格入口：提交字节，得到领域记录或隔离记录。"""

    def __init__(self) -> None:
        self.quarantines: list[QuarantineRecord] = []

    def submit_bytes(
        self, raw: bytes, file_name: str, *, received_at: str | None = None
    ) -> IngressResult:
        parsed = parse_document(raw)
        issues: list[Issue] = list(parsed.issues)
        record: DomainRecord | None = None
        if parsed.ok:
            issues.extend(
                validate_fields(
                    parsed.value, parsed.key_spans, _ENVELOPE_FIELDS, REQUIRED_FIELDS
                )
            )
            issues = _sort_issues(issues, parsed.text)
            if not issues:
                record = DomainRecord(
                    **{name: parsed.value[name] for name in REQUIRED_FIELDS}
                )

        if record is not None:
            return IngressResult(ok=True, record=record, quarantine=None)

        quarantine = make_quarantine(
            raw, file_name, issues, received_at=received_at
        )
        self.quarantines.append(quarantine)
        return IngressResult(ok=False, record=None, quarantine=quarantine)

    def submit_path(self, path: str | Path) -> IngressResult:
        path = Path(path)
        return self.submit_bytes(path.read_bytes(), path.name)


__all__ = [
    "EvidenceIngress",
    "EvidenceRejected",
    "FieldSpec",
    "IngressResult",
    "Issue",
    "ParsedDocument",
    "QuarantineRecord",
    "SUPPORTED_SCHEMA_VERSIONS",
    "enum_check",
    "iso_time",
    "make_quarantine",
    "non_empty_str",
    "parse_document",
    "positive_int",
    "validate_fields",
]
