"""联检工作流协调器：入口、保管链、结论、危急通知与崩溃恢复。

所有状态改变遵循 **先写 WAL（fsync）后改内存**：

* 恢复时按 WAL 重放，保管链事件与结论事件各自幂等，不会重复消耗样本；
* 危急通知以 ``critical:<incident>:<assay>:<result_id>`` 为去重键，重放只
  重建“已通知”台账，不再调用外部发送器，因此中断后续跑不会重复发出危急通知；
  不同结果（如新的晚到复测）仍各自通知一次；
* 结果以 ``result_id`` 幂等，结论以 incident 幂等。
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .chain import ChainLedger
from .conclusions import IssuedVersion, PanelRegistry, Receipt
from .errors import EvidenceError, Problem
from .intake import (
    IntakeRecord,
    IntakeRegistry,
    IngestResult,
    QuarantineEntry,
    validate_envelope,
)
from .strictjson import Node
from .wal import WriteAheadLog

Sender = Callable[[dict[str, Any]], None]


def outbox_sender(outbox: list[dict[str, Any]]) -> Sender:
    """默认发送器：把通知追加到进程内发件箱。"""

    def send(notice: dict[str, Any]) -> None:
        outbox.append(notice)

    return send


@dataclass
class WorkflowStats:
    wal_appended: int = 0
    notifications_sent: int = 0
    notifications_suppressed: int = 0


class IncidentHub:
    """组合入口台账、保管链、结论注册表和通知去重的单一协调器。"""

    def __init__(
        self,
        wal_path: Path | str,
        validator: Callable[[Node], Any] = validate_envelope,
        sender: Sender | None = None,
    ) -> None:
        self.wal = WriteAheadLog(wal_path)
        self.intake = IntakeRegistry(validator)
        self.chain = ChainLedger()
        self.panels = PanelRegistry()
        self.outbox: list[dict[str, Any]] = []
        self._sender: Sender = sender or outbox_sender(self.outbox)
        self._notified: set[str] = set()
        self._wal_quarantined_hashes: set[str] = set()
        self.stats = WorkflowStats()
        try:
            self._recover()
        except BaseException:
            self.wal.close()
            raise

    # ============================================================== 恢复

    def _recover(self) -> None:
        pending_critical: list[tuple[str, dict[str, Any]]] = []
        for entry in self.wal.replay():
            kind, payload = entry.kind, entry.payload
            if kind == "intake_accepted":
                record = IntakeRecord(**payload["record"])
                self.intake.restore_accepted(payload["file_name"], payload["digest"], record)
            elif kind == "quarantine":
                raw = base64.b64decode(payload["raw_b64"])
                quarantine = QuarantineEntry(
                    file_name=payload["file_name"],
                    byte_sha256=payload["byte_sha256"],
                    byte_length=payload["byte_length"],
                    raw=raw,
                    received_at=datetime.fromisoformat(payload["received_at"]),
                    stage=payload["stage"],
                    code=payload["code"],
                    problems=tuple(Problem(**p) for p in payload["problems"]),
                )
                self.intake.restore_quarantine(quarantine)
                self._wal_quarantined_hashes.add(quarantine.byte_sha256)
            elif kind == "chain_event":
                self.chain.apply(payload["event"])
            elif kind == "panel_event":
                self._apply_panel_event(payload["event"])
                if payload["event"]["type"] == "record_result":
                    pending_critical.append(
                        (payload["event"]["incident_id"], payload["event"]["data"])
                    )
            elif kind == "notification":
                # 重放只登记“已通知”事实，绝不再次调用发送器。
                self._notified.add(payload["key"])
            else:
                raise EvidenceError([Problem("wal_shape", f"未知 WAL 记录类型 {kind!r}")])

        # 崩溃可能发生在结果落 WAL 之后、危急通知落 WAL 之前。
        # 第一遍重建完 notification 去重台账后，对这些缺口只补发一次。
        for incident_id, data in pending_critical:
            if data.get("critical"):
                self._notify_critical(incident_id, data)

    # ============================================================== 证据入口

    def ingest_file(self, path: Path | str) -> IngestResult:
        path = Path(path)
        return self.ingest_bytes(path.read_bytes(), path.name)

    def ingest_bytes(self, raw: bytes, file_name: str) -> IngestResult:
        admission, result = self.intake.prepare(raw, file_name)
        if admission is None:
            # 仅当这是一个*新形成*的隔离时才写 WAL；同一坏文件原样重送在
            # 恢复前后都命中既有隔离哈希，不重复留存。
            if result.status == "quarantined" and result.entry is not None:
                if result.entry.byte_sha256 not in self._wal_quarantined_hashes:
                    self._wal_quarantine(result.entry)
                    self._wal_quarantined_hashes.add(result.entry.byte_sha256)
            return result
        # 接受路径同样遵循“先 WAL（fsync）后改内存”：WAL 中的记录永远不比
        # 内存状态旧，崩溃恢复以重放为准。
        record = admission.record
        if isinstance(record, IntakeRecord):
            record = replace(record, file_name=admission.file_name, byte_sha256=admission.digest)
        self.wal.append("intake_accepted", {
            "file_name": admission.file_name,
            "digest": admission.digest,
            "record": record.__dict__ if isinstance(record, IntakeRecord) else None,
        })
        self.stats.wal_appended += 1
        return self.intake.commit(admission)

    def _wal_quarantine(self, entry: QuarantineEntry) -> None:
        self.wal.append("quarantine", {
            "file_name": entry.file_name,
            "byte_sha256": entry.byte_sha256,
            "byte_length": entry.byte_length,
            "raw_b64": base64.b64encode(entry.raw).decode("ascii"),
            "received_at": entry.received_at.isoformat(),
            "stage": entry.stage,
            "code": entry.code,
            "problems": [
                {"code": p.code, "message": p.message, "line": p.line,
                 "column": p.column, "pointer": p.pointer}
                for p in entry.problems
            ],
        })
        self.stats.wal_appended += 1

    # ============================================================== 保管链

    def apply_chain_event(self, event: dict[str, Any]) -> Any:
        """外部构造的交接/拆分/耗用/补样事件。

        先在隔离的试算账本上验证语义（含数量守恒），通过后才写 WAL，
        保证坏事件永远不会落盘污染重放；事件本身的 event_id 幂等由账本保证。
        """

        ChainLedger.replay([*self.chain.events_for_replay(), event])
        self.wal.append("chain_event", {"event": event})
        self.stats.wal_appended += 1
        return self.chain.apply(event)

    def split_for_assay(
        self, incident_id: str, assay: str, *, parent_sample_id: str,
        child_sample_id: str, quantity: str, from_party: str, to_party: str,
        occurred_at: str,
    ) -> Any:
        """为某项检测从父样分样子样。确定性 event_id 使恢复/重试不重复拆分。"""

        event = {
            "event_id": f"{incident_id}:split:{assay}",
            "action": "split",
            "occurred_at": occurred_at,
            "sample_id": parent_sample_id,
            "child_sample_id": child_sample_id,
            "quantity": str(quantity),
            "from_party": from_party,
            "to_party": to_party,
            "assay": assay,
        }
        return self._chain_event_once(event)

    def consume_for_assay(
        self, incident_id: str, assay: str, *, sample_id: str,
        quantity: str, by_party: str, occurred_at: str,
    ) -> Any:
        """登记某项检测的样本耗用；同一 (事件, 检测) 组合绝不第二次扣减。"""

        event = {
            "event_id": f"{incident_id}:consume:{assay}",
            "action": "consume",
            "occurred_at": occurred_at,
            "sample_id": sample_id,
            "quantity": str(quantity),
            "by_party": by_party,
            "assay": assay,
        }
        return self._chain_event_once(event)

    def _chain_event_once(self, event: dict[str, Any]) -> Any:
        existing = self.chain._events.get(event["event_id"])
        if existing is not None:
            if existing == event:
                # 中断后继续未完成联检：事件已落库，原样重试直接幂等返回，
                # 不再写 WAL、不再扣减样本。
                return next(e for e in self.chain.entries if e.event_id == event["event_id"])
            raise EvidenceError([Problem(
                "event_id_conflict",
                f"event_id {event['event_id']!r} 已用于不同载荷", pointer="/event_id",
            )])
        # 新事件先在试算账本上验证数量守恒与保管链，通过才写 WAL。
        ChainLedger.replay([*self.chain.events_for_replay(), event])
        self.wal.append("chain_event", {"event": event})
        self.stats.wal_appended += 1
        return self.chain.apply(event)

    # ============================================================== 联检结论

    def open_panel(
        self, conclusion_id: str, incident_id: str,
        depended_assays: list[str] | tuple[str, ...] = ("morphology", "toxin", "molecular"),
    ) -> Any:
        event = {
            "type": "open_conclusion",
            "conclusion_id": conclusion_id,
            "incident_id": incident_id,
            "depended_assays": list(depended_assays),
        }
        # 试算：重复开立/非法依赖集合在写 WAL 前被拒绝。
        PanelRegistry.replay([*self.panels.events_for_replay(), event])
        self.wal.append("panel_event", {"event": event})
        self.stats.wal_appended += 1
        return self._apply_panel_event(event)

    def record_result(self, incident_id: str, data: dict[str, Any]) -> tuple[str, Receipt]:
        """登记检测结果；若标记为危急则恰好发送一次危急通知。

        先在试算注册表上验证（结论存在、assay 在依赖集合内、result_id 未被
        异内容复用），通过后才写 WAL；重复结果原样重送不写 WAL、不发通知。
        """

        event = {"type": "record_result", "incident_id": incident_id, "data": data}
        probe = PanelRegistry.replay([*self.panels.events_for_replay(), event])
        disposition = probe.conclusions[incident_id].receipts[-1].disposition
        if disposition != "duplicate":
            self.wal.append("panel_event", {"event": event})
            self.stats.wal_appended += 1
        _, receipt = self._apply_panel_event(event)
        if disposition != "duplicate" and data.get("critical"):
            self._notify_critical(incident_id, data)
        return disposition, receipt

    def issue_conclusion(self, incident_id: str, issued_at: str, summary: str = "") -> IssuedVersion:
        event = {
            "type": "issue", "incident_id": incident_id,
            "issued_at": issued_at, "summary": summary,
        }
        # 试算：依赖未齐/重复签发在写 WAL 前被拒绝。
        PanelRegistry.replay([*self.panels.events_for_replay(), event])
        self.wal.append("panel_event", {"event": event})
        self.stats.wal_appended += 1
        return self._apply_panel_event(event)

    def _apply_panel_event(self, event: dict[str, Any]) -> Any:
        kind = event["type"]
        if kind == "open_conclusion":
            return self.panels.open_conclusion(
                event["conclusion_id"], event["incident_id"], event["depended_assays"]
            )
        if kind == "record_result":
            return self.panels.record_result(event["incident_id"], event["data"])
        if kind == "issue":
            return self.panels.issue(
                event["incident_id"], event["issued_at"], event.get("summary", "")
            )
        raise EvidenceError([Problem("invalid_value", f"未知结论事件类型 {kind!r}")])

    # ============================================================== 危急通知

    def _notify_critical(self, incident_id: str, data: dict[str, Any]) -> None:
        # 去重粒度为 (事件, 检测, 结果)：同一条危急结果无论重试或恢复多少次只发一次；
        # 不同 result_id 的新加危急结果（如晚到复测）仍各自通知一次。
        key = f"critical:{incident_id}:{data['assay']}:{data['result_id']}"
        if key in self._notified:
            # 恢复后续跑或重复送样：危急通知绝不第二次发出。
            self.stats.notifications_suppressed += 1
            return
        notice = {
            "key": key,
            "kind": "critical_value",
            "incident_id": incident_id,
            "assay": data["assay"],
            "result_id": data["result_id"],
            "sample_id": data["sample_id"],
            "channel": "clinical",
            "sent_at": data["received_at"],
            "detail": data.get("critical_note", "野生菌检测危急值，请立即临床处置"),
        }
        # 先落 WAL 再发送：崩溃恢复时以 WAL 为准，不重复通知。
        self.wal.append("notification", notice)
        self.stats.wal_appended += 1
        self._notified.add(key)
        self._sender(notice)
        self.stats.notifications_sent += 1

    # ============================================================== 查询/关闭

    def family_report(self, root_sample_id: str) -> dict[str, Any]:
        return self.chain.family_report(root_sample_id)

    def assert_integrity(self) -> None:
        self.chain.assert_all_conserved()

    def close(self) -> None:
        self.wal.close()

    def __enter__(self) -> "IncidentHub":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
