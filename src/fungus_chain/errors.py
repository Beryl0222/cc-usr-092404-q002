"""证据链相关错误类型。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Problem:
    """单条可定位的拒绝原因。"""

    code: str
    message: str
    #: 1 基行号 / 0 基列号（相对原始字节解码后的文本）；与 json 错误位置含义一致
    line: int | None = None
    column: int | None = None
    #: JSON 指针风格的字段路径，如 events/3/quantity
    pointer: str | None = None

    def location(self) -> str:
        bits: list[str] = []
        if self.pointer:
            bits.append(self.pointer)
        if self.line is not None:
            bits.append(f"line {self.line}")
        if self.column is not None:
            bits.append(f"column {self.column}")
        return " ".join(bits) if bits else "<unknown location>"


class EvidenceError(ValueError):
    """所有入口/领域拒绝的基类，携带稳定问题列表。"""

    def __init__(self, problems: list[Problem] | Problem):
        if isinstance(problems, Problem):
            problems = [problems]
        self.problems: list[Problem] = list(problems)
        super().__init__("; ".join(f"[{p.code}] {p.message} ({p.location()})" for p in self.problems))


class StrictJsonError(EvidenceError):
    """原始字节不是唯一、完整、可解码的一个 JSON 值。"""


class SchemaRejected(EvidenceError):
    """JSON 结构合法，但违反字段合同（未知字段、类型、时间等）。"""


class ChainViolation(EvidenceError):
    """保管链/数量守恒被破坏。"""


class WorkflowConflict(EvidenceError):
    """事件顺序或幂等键冲突（如同名异内容、重复签发）。"""
