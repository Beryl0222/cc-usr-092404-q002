"""服务中断恢复测试：不重复消耗样本、不重复发出危急通知。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fungus_chain import IncidentHub, StrictJsonError  # noqa: E402
from fungus_chain.wal import WriteAheadLog  # noqa: E402


def make_handoff():
    return {
        "event_id": "in-S0", "action": "handoff",
        "occurred_at": "2026-09-20T09:00:00+08:00",
        "sample_id": "S0", "incident_id": "INC1", "matrix": "剩余菌物",
        "unit": "g", "quantity": "50", "from_party": "急诊", "to_party": "疾控",
    }


def split(assay, child, qty, to_party, minute):
    return {
        "event_id": f"INC1:split:{assay}", "action": "split",
        "occurred_at": f"2026-09-20T09:{minute:02d}:00+08:00",
        "sample_id": "S0", "child_sample_id": child, "quantity": qty,
        "from_party": "疾控", "to_party": to_party, "assay": assay,
    }


def critical_toxin_result():
    return {
        "result_id": "r-t", "assay": "toxin", "sample_id": "S-t",
        "occurred_at": "2026-09-20T11:10:00+08:00",
        "received_at": "2026-09-20T11:15:00+08:00",
        "payload": {"amatoxin": 1.2}, "critical": True,
        "critical_note": "鹅膏毒肽阳性",
    }


class CrashRecoveryTest(unittest.TestCase):
    def test_resume_after_restart_does_not_reconsume_or_renotify(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "wal.jsonl"

            # 第一次进程：交接、分样、毒素室耗用 5g、登记危急毒素结果
            hub = IncidentHub(wal)
            hub.apply_chain_event(make_handoff())
            hub.apply_chain_event(split("toxin", "S-t", "20", "毒素室", 11))
            hub.consume_for_assay(
                "INC1", "toxin", sample_id="S-t", quantity="5", by_party="毒素室",
                occurred_at="2026-09-20T10:05:00+08:00")
            hub.open_panel("C1", "INC1")
            disposition, _ = hub.record_result("INC1", critical_toxin_result())
            self.assertEqual(disposition, "draft_updated")
            self.assertEqual(len(hub.outbox), 1)
            consumed_before = str(hub.chain.samples["S-t"].consumed)
            hub.close()

            # 服务中断：新进程从同一 WAL 恢复，继续未完成联检
            hub2 = IncidentHub(wal)
            self.assertEqual(str(hub2.chain.samples["S-t"].consumed), consumed_before)
            # 恢复时不重新发送任何通知（通知已在崩溃前落 WAL）
            self.assertEqual(hub2.outbox, [])
            self.assertEqual(hub2.stats.notifications_sent, 0)

            # 客户端因未收到应答而重试同一批操作：必须全部幂等
            hub2.consume_for_assay(
                "INC1", "toxin", sample_id="S-t", quantity="5", by_party="毒素室",
                occurred_at="2026-09-20T10:05:00+08:00")
            self.assertEqual(str(hub2.chain.samples["S-t"].consumed), "5")
            d2, _ = hub2.record_result("INC1", critical_toxin_result())
            self.assertEqual(d2, "duplicate")
            self.assertEqual(hub2.outbox, [])
            self.assertEqual(hub2.stats.notifications_suppressed, 1)

            # 继续把联检做完：形态学与分子结果到达后签发
            hub2.apply_chain_event(split("morphology", "S-m", "10", "形态室", 10))
            hub2.apply_chain_event(split("molecular", "S-g", "15", "分子室", 12))
            hub2.record_result("INC1", {
                "result_id": "r-m", "assay": "morphology", "sample_id": "S-m",
                "occurred_at": "2026-09-20T11:00:00+08:00",
                "received_at": "2026-09-20T11:05:00+08:00",
                "payload": {"species": "鹅膏属"}, "critical": False})
            hub2.record_result("INC1", {
                "result_id": "r-g", "assay": "molecular", "sample_id": "S-g",
                "occurred_at": "2026-09-20T11:20:00+08:00",
                "received_at": "2026-09-20T11:25:00+08:00",
                "payload": {"match": "A. phalloides"}, "critical": False})
            hub2.issue_conclusion("INC1", "2026-09-20T12:00:00+08:00")
            hub2.assert_integrity()
            hub2.close()

            # 再次重开：最终状态稳定
            hub3 = IncidentHub(wal)
            self.assertEqual(str(hub3.chain.samples["S-t"].consumed), "5")
            self.assertEqual(len(hub3.panels.conclusions["INC1"].issued), 1)
            self.assertTrue(hub3.family_report("S0")["conserved"])
            hub3.close()

    def test_crash_between_result_wal_and_notification_wal_resends_once(self):
        """崩溃窗口：危急结果已落 WAL、通知尚未落 WAL，恢复时补发且只补发一次。"""

        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "wal.jsonl"
            # 手工构造磁盘状态（等价于在该窗口内掉电）
            log = WriteAheadLog(wal)
            log.append("chain_event", {"event": make_handoff()})
            log.append("chain_event", {"event": split("toxin", "S-t", "20", "毒素室", 11)})
            log.append("panel_event", {"event": {
                "type": "open_conclusion", "conclusion_id": "C1",
                "incident_id": "INC1",
                "depended_assays": ["morphology", "toxin", "molecular"],
            }})
            log.append("panel_event", {"event": {
                "type": "record_result", "incident_id": "INC1",
                "data": critical_toxin_result(),
            }})
            log.close()

            hub = IncidentHub(wal)
            self.assertEqual(len(hub.outbox), 1)  # 缺口被补发
            self.assertEqual(hub.outbox[0]["result_id"], "r-t")
            hub.close()

            hub2 = IncidentHub(wal)
            self.assertEqual(hub2.outbox, [])  # 第二次恢复不再补发
            hub2.close()

    def test_quarantine_and_name_hold_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "wal.jsonl"
            good = json.dumps({
                "schema_version": 1, "record_id": "sample-016",
                "domain": "fungus_chain",
                "occurred_at": "2026-09-20T09:00:00+08:00",
                "revision": 1, "source": "业务样例",
            }, ensure_ascii=False).encode("utf-8")
            hub = IncidentHub(wal)
            self.assertEqual(hub.ingest_bytes(good, "handoff.json").status, "accepted")
            # 同名异内容 -> 暂停
            other = good.replace(b"sample-016", b"sample-017")
            held = hub.ingest_bytes(other, "handoff.json")
            self.assertEqual(held.status, "quarantined")
            self.assertEqual(held.entry.code, "name_content_conflict")
            # 重复键坏文件 -> 隔离
            dup = good.replace(b'"record_id": "sample-016"',
                               b'"record_id": "a", "record_id": "b"', 1)
            q = hub.ingest_bytes(dup, "other.json")
            self.assertEqual(q.status, "quarantined")
            self.assertEqual(q.entry.code, "duplicate_key")
            hub.close()

            hub2 = IncidentHub(wal)
            # 恢复后：原文件仍幂等、暂停仍生效、坏文件仍隔离
            self.assertEqual(hub2.ingest_bytes(good, "handoff.json").status, "duplicate")
            # 重送同一份被暂停的字节：返回原始隔离记录，不重复登记
            same = hub2.ingest_bytes(other, "handoff.json")
            self.assertEqual(same.status, "quarantined")
            self.assertEqual(same.entry.code, "name_content_conflict")
            # 暂停名下出现*第三份*内容：以 name_hold 拒绝关联
            third = good.replace(b"sample-016", b"sample-018")
            held_new = hub2.ingest_bytes(third, "handoff.json")
            self.assertEqual(held_new.status, "quarantined")
            self.assertEqual(held_new.entry.code, "name_hold")
            dup_again = hub2.ingest_bytes(dup, "other.json")
            self.assertEqual(dup_again.status, "quarantined")
            # 原始字节仍随隔离记录保留
            self.assertEqual(dup_again.entry.raw, dup)
            hub2.close()

    def test_corrupted_wal_is_detected_with_position(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "wal.jsonl"
            wal.write_bytes(b'{"seq": 1, "kind": "x", "payload": {}}\n'
                           b'{broken\n')
            with self.assertRaises(StrictJsonError) as ctx:
                IncidentHub(wal)
            self.assertIn("WAL 第 2 行损坏", str(ctx.exception))

    def test_wal_seq_gap_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "wal.jsonl"
            wal.write_bytes(
                b'{"seq": 1, "kind": "x", "payload": {}}\n'
                b'{"seq": 3, "kind": "x", "payload": {}}\n'
            )
            with self.assertRaises(StrictJsonError) as ctx:
                IncidentHub(wal)
            self.assertEqual(ctx.exception.problems[0].code, "wal_seq_gap")


if __name__ == "__main__":
    unittest.main()
