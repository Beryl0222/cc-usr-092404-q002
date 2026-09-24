"""项目已确认的最小数据合同。

``load_record`` 现在是严格证据入口：重复键、尾随内容、未知字段、非法时间等
问题不再被静默吞掉，而是抛出携带可定位问题列表的 :class:`EvidenceError`。
需要保留原始字节与问题位置时，使用 :class:`IntakeRegistry`。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .intake import validate_envelope
from .strictjson import parse_bytes


@dataclass(frozen=True)
class DomainRecord:
    schema_version: int
    record_id: str
    domain: str
    occurred_at: str
    revision: int
    source: str


def load_record(path: Path | str) -> DomainRecord:
    """从字节读取一条最小合同记录。

    任何歧义（重复键、尾随内容）或合同违反（未知字段、非法时间等）都抛出
    :class:`~fungus_chain.errors.EvidenceError`，其 ``problems`` 携带行列位置。
    """

    raw = Path(path).read_bytes()
    node = parse_bytes(raw)
    intake = validate_envelope(node)
    return DomainRecord(
        schema_version=intake.schema_version,
        record_id=intake.record_id,
        domain=intake.domain,
        occurred_at=intake.occurred_at,
        revision=intake.revision,
        source=intake.source,
    )
