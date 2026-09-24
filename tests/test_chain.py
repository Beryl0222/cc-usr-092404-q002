"""保管链与分样守恒测试。

一次误食事件分送形态学、毒素、分子检测多个样本；交接、拆分、耗用、
补样与结论修订必须维持父子数量及保管链。
"""

import tempfile
import unittest

from scenario import INCIDENT, fresh_ledger, run_standard, standard_steps

from fungus_chain import BusinessRuleError, messages as m
from fungus_chain.ledger import ChainLedger


def stamp(minute: int) -> str:
    return f"2026-09-20T09:{minute:02d}:00+08:00"


class ChainOfCustodyTest(unittest.TestCase):
    def test_intake_registers_three_test_samples_for_one_incident(self):
        ledger = fresh_ledger(tempfile.mkdtemp())
        raw = m.intake(
            message_id="in-1",
            occurred_at=stamp(0),
            incident_id=INCIDENT,
            samples=[
                {
                    "sample_id": "a",
                    "specimen": "菌残体",
                    "tests": ["morphology", "toxin", "molecular"],
                    "quantity": 6,
                    "unit": "g",
                }
            ],
        )
        out = ledger.submit_bytes(raw, "intake.json")
        self.assertEqual(out.kind, "applied")
        sample = ledger.samples["a"]
        self.assertEqual(sample.incident_id, INCIDENT)
        self.assertEqual(sample.tests, ("morphology", "toxin", "molecular"))
        self.assertEqual(sample.root_sample_id, "a")
        # 保管链事件带来源文件名与字节摘要。
        event = ledger.events[-1]
        self.assertEqual(event.kind, "intake")
        self.assertEqual(event.file_name, "intake.json")
        self.assertRegex(event.sha256, r"^[0-9a-f]{64}$")

    def test_split_conserves_parent_child_quantities(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:2])
        parent = ledger.samples["s-bulk"]
        self.assertEqual(parent.quantity_remaining, 1)
        self.assertEqual(
            sorted(parent.children), ["s-mol", "s-morph", "s-tox"]
        )
        for child_id in parent.children:
            child = ledger.samples[child_id]
            self.assertEqual(child.parent_sample_id, "s-bulk")
            self.assertEqual(child.root_sample_id, "s-bulk")
            self.assertEqual(child.origin, "split")
        report = ledger.mass_balance("s-bulk")
        # 初始 10 = 三个子样各 3 + 父样留 1。
        self.assertEqual(report["initial_quantity"], 10)
        self.assertEqual(report["remaining_total"], 10)
        self.assertEqual(report["consumed_total"], 0)
        self.assertEqual(report["difference"], 0)

    def test_split_that_loses_material_is_rejected_atomically(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:1])
        # 子样合计 9，申报剩余 2，合计 11 > 10：数量凭空增加。
        bad = m.split(
            message_id="bad-split",
            occurred_at=stamp(3),
            parent_sample_id="s-bulk",
            children=[
                {"sample_id": "c1", "quantity": 3},
                {"sample_id": "c2", "quantity": 3},
                {"sample_id": "c3", "quantity": 3},
            ],
            remaining_quantity=2,
        )
        outcome = ledger.submit_bytes(bad, "bad-split.json")
        self.assertEqual(outcome.kind, "rejected")
        self.assertIn("不守恒", outcome.reason)
        # 原子性：任何子样都不得登记，父样数量不变。
        self.assertNotIn("c1", ledger.samples)
        self.assertEqual(ledger.samples["s-bulk"].quantity_remaining, 10)
        self.assertEqual(ledger.samples["s-bulk"].children, [])

    def test_split_that_destroys_material_is_rejected(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:1])
        bad = m.split(
            message_id="bad-split-2",
            occurred_at=stamp(4),
            parent_sample_id="s-bulk",
            children=[{"sample_id": "c1", "quantity": 3}],
            remaining_quantity=3,  # 3+3=6 < 10，4g 去向不明
        )
        outcome = ledger.submit_bytes(bad, "bad-split-2.json")
        self.assertEqual(outcome.kind, "rejected")
        self.assertIn("差额 4", outcome.reason)

    def test_consume_and_full_tree_mass_balance(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:5])
        # 三个子样各耗用 2g：10 = 父留1 + 子样各留1(共3) + 已耗 6。
        report = ledger.mass_balance("s-bulk")
        self.assertEqual(report["remaining_total"], 4)
        self.assertEqual(report["consumed_total"], 6)
        self.assertEqual(report["difference"], 0)
        ledger.assert_balanced()
        self.assertEqual(ledger.samples["s-morph"].consumed_for, {"morphology": 2})

    def test_consume_twice_for_same_test_is_rejected(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:5])
        again = m.consume(
            message_id="again",
            occurred_at=stamp(8),
            sample_id="s-morph",
            test="morphology",
            quantity=1,
        )
        outcome = ledger.submit_bytes(again, "again.json")
        self.assertEqual(outcome.kind, "rejected")
        self.assertIn("已耗用", outcome.reason)
        # 数量未被第二次耗用改动。
        self.assertEqual(ledger.samples["s-morph"].quantity_remaining, 1)

    def test_consume_more_than_remaining_rejected(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:2])
        raw = m.consume(
            message_id="over",
            occurred_at=stamp(5),
            sample_id="s-morph",
            test="morphology",
            quantity=9,
        )
        outcome = ledger.submit_bytes(raw, "over.json")
        self.assertEqual(outcome.kind, "rejected")
        self.assertIn("耗用超量", outcome.reason)

    def test_consume_test_not_assigned_rejected(self):
        # s-morph 仅分送形态学，不得用它做毒素检测耗用。
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:2])
        raw = m.consume(
            message_id="wrong",
            occurred_at=stamp(5),
            sample_id="s-morph",
            test="toxin",
            quantity=1,
        )
        outcome = ledger.submit_bytes(raw, "wrong.json")
        self.assertEqual(outcome.kind, "rejected")
        self.assertIn("不含", outcome.reason)
        self.assertEqual(ledger.samples["s-morph"].quantity_remaining, 3)

    def test_supplement_adds_independent_root_and_conserves(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:5])
        supp = m.supplement(
            message_id="supp-2",
            occurred_at=stamp(9),
            incident_id=INCIDENT,
            sample_id="s-sup",
            specimen="第二次呕吐物",
            tests=["morphology", "toxin"],
            quantity=4,
            unit="g",
            reason="首样形态学复检需要",
        )
        outcome = ledger.submit_bytes(supp, "supp.json")
        self.assertEqual(outcome.kind, "applied")
        sample = ledger.samples["s-sup"]
        self.assertEqual(sample.origin, "supplement")
        self.assertEqual(sample.parent_sample_id, None)
        self.assertEqual(sample.root_sample_id, "s-sup")
        # 补样是独立的新分样树，不影响原树平衡。
        self.assertEqual(ledger.mass_balance("s-bulk")["difference"], 0)
        self.assertEqual(ledger.mass_balance("s-sup")["difference"], 0)
        ledger.assert_balanced()

    def test_conclusion_revision_before_issue_is_versioned(self):
        steps = standard_steps()[:6]
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=steps)
        revise = m.revise_conclusion(
            message_id="rev-1",
            occurred_at=stamp(11),
            incident_id=INCIDENT,
            conclusion_id="con-1",
            content="修订：形态学高度疑似致命鹅膏。",
        )
        self.assertEqual(ledger.submit_bytes(revise, "revise.json").kind, "applied")
        conclusion = ledger.conclusions["con-1"]
        self.assertEqual([v.revision for v in conclusion.versions], [1, 2])
        self.assertEqual([v.kind for v in conclusion.versions], ["create", "revise"])
        self.assertFalse(conclusion.issued)

    def test_supplement_payload_rejects_unknown_and_bad_tests(self):
        import json

        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:1])
        payload = {
            "schema_version": 1,
            "message_id": "supp-bad",
            "command": "supplement",
            "occurred_at": "2026-09-20T09:00:00+08:00",
            "payload": {
                "incident_id": INCIDENT,
                "sample_id": "s-sup",
                "specimen": "菌汤",
                "tests": ["toxin", "cult"],
                "quantity": 2,
                "unit": "g",
                "reason": "复检",
                "courier": "张某",  # 未知字段
            },
        }
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        outcome = ledger.submit_bytes(raw, "supp-bad.json")
        self.assertEqual(outcome.kind, "quarantined")
        codes = {i.code for i in outcome.quarantine.issues}
        self.assertIn("unknown_field", codes)
        self.assertTrue(
            any(i.path == "/payload/tests/1" for i in outcome.quarantine.issues)
        )
        self.assertNotIn("s-sup", ledger.samples)

    def test_quarantine_is_stable_on_identical_bad_resubmit(self):
        ledger = fresh_ledger(tempfile.mkdtemp())
        bad = (
            b'{"schema_version":1,"message_id":"x","message_id":"y",'
            b'"command":"consume","occurred_at":"2026-09-20T09:00:00+08:00",'
            b'"payload":{"sample_id":"s","test":"toxin","quantity":1}}'
        )
        first = ledger.submit_bytes(bad, "bad.json")
        second = ledger.submit_bytes(bad, "bad.json")  # 原样重送同一坏文件
        self.assertEqual(first.kind, second.kind, "quarantined")
        self.assertIs(first.quarantine, second.quarantine)
        self.assertEqual(len(ledger.quarantines), 1)  # 不重复堆积隔离记录
        self.assertEqual(ledger.events[-1].kind, "quarantine_repeated")

    def test_every_custody_event_carries_evidence_provenance(self):
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:5])
        for event in ledger.events:
            self.assertTrue(event.seq)
            self.assertIn(
                event.kind,
                {
                    "intake",
                    "split",
                    "consume",
                },
            )
            self.assertIsNotNone(event.message_id)
            self.assertRegex(event.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual([e.seq for e in ledger.events], [1, 2, 3, 4, 5])


if __name__ == "__main__":
    unittest.main()
