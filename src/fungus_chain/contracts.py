"""项目确认的最小数据合同及其严格读取入口。

``load_record`` 不再静默接受重复键等歧义输入：解析失败会抛出
:class:`fungus_chain.ingress.EvidenceRejected`，异常对象携带保留了原始字节
摘要与问题位置的隔离记录。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = ["DomainRecord", "load_record"]


@dataclass(frozen=True)
class DomainRecord:
    schema_version: int
    record_id: str
    domain: str
    occurred_at: str
    revision: int
    source: str


def load_record(path: str | Path):
    """严格读取一条领域记录；任何入口问题都以隔离记录形式抛出。"""
    from .ingress import EvidenceIngress, EvidenceRejected  # 延迟导入避免循环

    path = Path(path)
    ingress = EvidenceIngress()
    return ingress.submit_path(path).unwrap()
