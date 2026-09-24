"""保管链测试：交接、拆分、耗用、补样与父子数量守恒。"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fungus_chain import ChainLedger, ChainViolation  # noqa: E402

T0 = "2026-09-20T09:00:00+08:00"
T1 = "2026-09-20T09:30:00+08:00"
T2 = "2026-09-20T10:00:00+08:00"

PARTY = {"morphology": "形态学室", "toxin": "毒素室", "molecular": "分子室"}


def handoff(sample="S0", qty="50", **kw):
    ev = {
        "event_id": f"in-{sample}", "action": "handoff", "occurred_at": T0,
        "sample_id": sample, "incident_id": "INC1", "matrix": "剩余菌物",
        "unit": "g", "quantity": qty, "from_party": "急诊", "to_party": "疾控",
    }
    ev.update(kw)
    return ev


def split(child, qty, assay, eid=None, **kw):
    ev = {
        "event_id": eid or f"sp-{child}", "action": "split", "occurred_at": T1,
        "sample_id": "S0", "child_sample_id": child, "quantity": qty,
        "from_party": "疾控", "to_party": PARTY[assay], "assay": assay,
    }
    ev.update(kw)
    return ev


def consume(sample, qty, party, assay, eid=None, **kw):
    ev = {
        "event_id": eid or f"cs-{sample}", "action": "consume", "occurred_at": T2,
        "sample_id": sample, "quantity": qty, "by_party": party, "assay": assay,
    }
    ev.update(kw)
    return ev


class ChainConservationTest(unittest.TestCase):
    def build_panel_split(self):
        ledger = ChainLedger()
        ledger.apply(handoff())
        ledger.apply(split("S-m", "10", "morphology"))
        ledger.apply(split("S-t", "20", "toxin"))
        ledger.apply(split("S-g", "15", "molecular"))
        return ledger

    def test_split_conservation_across_family(self):
        ledger = self.build_panel_split()
        report = ledger.family_report("S0")
        self.assertTrue(report["conserved"], report)
        self.assertEqual(report["external_input"], "50")
        self.assertEqual(report["split_out_internal"], "45")
        self.assertEqual(report["child_received_internal"], "45")
        self.assertEqual(report["balance"], "50")  # 尚未耗用
        self.assertEqual(ledger.samples["S0"].balance.__class__.__name__, "Decimal")

    def test_consume_after_split_keeps_family_totals(self):
        ledger = self.build_panel_split()
        ledger.apply(consume("S-m", "3", "形态学室", "morphology"))
        ledger.apply(consume("S-t", "7", "毒素室", "toxin"))
        ledger.apply(consume("S-g", "2", "分子室", "molecular"))
        report = ledger.family_report("S0")
        self.assertTrue(report["conserved"])
        self.assertEqual(report["consumed"], "12")
        self.assertEqual(report["balance"], "38")  # 50 - 12
        # 逐样本结余
        self.assertEqual(str(ledger.samples["S0"].balance), "5")
        self.assertEqual(str(ledger.samples["S-m"].balance), "7")
        self.assertEqual(str(ledger.samples["S-t"].balance), "13")
        self.assertEqual(str(ledger.samples["S-g"].balance), "13")
        ledger.assert_all_conserved()

    def test_cannot_split_more_than_parent_balance(self):
        ledger = self.build_panel_split()  # 父样仅剩 5
        with self.assertRaises(ChainViolation) as ctx:
            ledger.apply(split("S-x", "6", "toxin", eid="sp-x"))
        self.assertEqual(ctx.exception.problems[0].code, "conservation_violation")
        # 拒绝后家族仍然守恒，且没有留下 S-x
        self.assertNotIn("S-x", ledger.samples)
        ledger.assert_all_conserved()

    def test_cannot_consume_more_than_sample_balance(self):
        ledger = self.build_panel_split()
        with self.assertRaises(ChainViolation) as ctx:
            ledger.apply(consume("S-m", "11", "形态学室", "morphology"))
        self.assertEqual(ctx.exception.problems[0].code, "conservation_violation")
        self.assertEqual(str(ledger.samples["S-m"].consumed), "0")

    def test_replenish_balances_further_consumption(self):
        ledger = self.build_panel_split()
        ledger.apply(consume("S-t", "20", "毒素室", "toxin"))  # 全部耗尽
        with self.assertRaises(ChainViolation):
            ledger.apply(consume("S-t", "1", "毒素室", "toxin", eid="cs-t2"))
        # 补样后可继续耗用，家族守恒把补样计入外部进入量
        ledger.apply({
            "event_id": "rp-t", "action": "replenish", "occurred_at": T2,
            "sample_id": "S-t", "quantity": "8", "from_party": "急诊补样", "reason": "复检",
        })
        ledger.apply(consume("S-t", "5", "毒素室", "toxin", eid="cs-t3"))
        report = ledger.family_report("S0")
        self.assertTrue(report["conserved"], report)
        self.assertEqual(report["external_input"], "58")  # 50 + 8
        self.assertEqual(report["consumed"], "25")
        self.assertEqual(report["balance"], "33")

    def test_custody_chain_is_enforced(self):
        ledger = self.build_panel_split()
        # 形态室持有的样本，毒素室不能耗用
        with self.assertRaises(ChainViolation) as ctx:
            ledger.apply(consume("S-m", "1", "毒素室", "toxin", eid="cs-wrong"))
        self.assertEqual(ctx.exception.problems[0].code, "custody_gap")
        # 保管转移后新保管方可以操作
        ledger.apply(handoff(sample="S-m", qty="0", from_party="形态学室",
                             to_party="毒素室", eid="tr-m"))
        ledger.apply(consume("S-m", "1", "毒素室", "toxin", eid="cs-after"))
        self.assertEqual(str(ledger.samples["S-m"].consumed), "1")

    def test_transfer_without_intake_fields(self):
        ledger = ChainLedger()
        ledger.apply(handoff())
        ledger.apply({
            "event_id": "tr1", "action": "handoff", "occurred_at": T1,
            "sample_id": "S0", "quantity": "0",
            "from_party": "疾控", "to_party": "上级实验室",
        })
        self.assertEqual(ledger.samples["S0"].custodian, "上级实验室")

    def test_duplicate_event_is_idempotent_but_changed_payload_rejected(self):
        ledger = self.build_panel_split()
        ev = split("S-m", "10", "morphology")
        before = str(ledger.samples["S0"].split_out)
        returned = ledger.apply(ev)  # 原样重放
        self.assertEqual(str(ledger.samples["S0"].split_out), before)
        self.assertEqual(returned.event_id, ev["event_id"])
        changed = dict(ev, quantity="11")
        with self.assertRaises(ChainViolation) as ctx:
            ledger.apply(changed)
        self.assertEqual(ctx.exception.problems[0].code, "event_id_conflict")

    def test_unknown_sample_and_bad_time_rejected_before_record(self):
        ledger = ChainLedger()
        with self.assertRaises(ChainViolation) as ctx:
            ledger.apply(consume("ghost", "1", "疾控", "toxin"))
        self.assertEqual(ctx.exception.problems[0].code, "unknown_sample")
        ledger.apply(handoff())
        bad = split("S-m", "10", "morphology", occurred_at="2026-09-20 09:30")
        with self.assertRaises(ChainViolation) as ctx:
            ledger.apply(bad)
        self.assertEqual(ctx.exception.problems[0].code, "invalid_time")

    def test_chain_entries_record_balance_after(self):
        ledger = self.build_panel_split()
        ledger.apply(consume("S-m", "4", "形态学室", "morphology"))
        last = ledger.entries[-1]
        self.assertEqual(last.sample_id, "S-m")
        self.assertEqual(last.balance_after, "6")
        self.assertEqual(last.custodian_after, "形态学室")

    def test_replay_rebuilds_identical_ledger(self):
        ledger = self.build_panel_split()
        ledger.apply(consume("S-t", "9", "毒素室", "toxin"))
        rebuilt = ChainLedger.replay(ledger.events_for_replay())
        self.assertEqual(
            {k: v.snapshot() for k, v in rebuilt.samples.items()},
            {k: v.snapshot() for k, v in ledger.samples.items()},
        )
        self.assertEqual(len(rebuilt.entries), len(ledger.entries))


if __name__ == "__main__":
    unittest.main()
