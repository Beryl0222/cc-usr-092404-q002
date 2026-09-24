"""联检结论测试：草稿更新、签发冻结、晚到结果追加更正与回执。"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fungus_chain import PanelRegistry, WorkflowConflict  # noqa: E402

T = "2026-09-20T11:00:00+08:00"


def result(rid, assay, *, critical=False, received_at=None, payload=None):
    return {
        "result_id": rid,
        "assay": assay,
        "sample_id": f"S-{assay[0]}",
        "occurred_at": T,
        "received_at": received_at or T,
        "payload": payload or {"value": rid},
        "critical": critical,
    }


def three_results(registry, incident="INC1"):
    registry.record_result(incident, result("r-m", "morphology"))
    registry.record_result(incident, result("r-t", "toxin"))
    registry.record_result(incident, result("r-g", "molecular"))


class PanelRuleTest(unittest.TestCase):
    def setUp(self):
        self.registry = PanelRegistry()
        self.registry.open_conclusion("C1", "INC1", ["morphology", "toxin", "molecular"])

    def test_late_result_updates_only_unsigned_draft(self):
        # 仅形态学先到，草稿可被晚到的毒素/分子结果持续更新
        d1, _ = self.registry.record_result("INC1", result("r-m", "morphology"))
        self.assertEqual(d1, "draft_updated")
        panel = self.registry.conclusions["INC1"]
        self.assertEqual(panel.draft_revision, 1)
        d2, _ = self.registry.record_result("INC1", result("r-t", "toxin"))
        self.assertEqual(d2, "draft_updated")
        self.assertEqual(panel.draft_revision, 2)
        self.assertFalse(panel.is_issued)
        self.assertEqual(panel.missing_assays(), ["molecular"])

    def test_cannot_issue_with_incomplete_panel(self):
        self.registry.record_result("INC1", result("r-m", "morphology"))
        with self.assertRaises(WorkflowConflict) as ctx:
            self.registry.issue("INC1", T)
        self.assertEqual(ctx.exception.problems[0].code, "incomplete_panel")

    def test_issued_version_is_frozen(self):
        three_results(self.registry)
        self.registry.issue("INC1", T, summary="初版结论")
        panel = self.registry.conclusions["INC1"]
        # 重复签发被拒绝
        with self.assertRaises(WorkflowConflict) as ctx:
            self.registry.issue("INC1", T, summary="再版")
        self.assertEqual(ctx.exception.problems[0].code, "already_issued")
        self.assertEqual(len(panel.issued), 1)

    def test_late_result_after_issue_appends_amendment_and_receipt(self):
        three_results(self.registry)
        version = self.registry.issue("INC1", "2026-09-20T12:00:00+08:00", summary="初版")
        frozen = version.content_sha256

        disposition, receipt = self.registry.record_result(
            "INC1",
            result("r-t-late", "toxin", received_at="2026-09-20T15:00:00+08:00",
                   payload={"amatoxin": 1.4}),
        )
        self.assertEqual(disposition, "amendment")
        self.assertEqual(receipt.disposition, "amendment")
        self.assertEqual(receipt.result_id, "r-t-late")
        self.assertTrue(receipt.amendment_id)

        panel = self.registry.conclusions["INC1"]
        # 已签发版本的指纹与结果集合完全不变
        self.assertEqual(panel.current_version.content_sha256, frozen)
        self.assertEqual(panel.current_version.result_ids, ("r-m", "r-t", "r-g"))
        # 更正与接收回执作为追加记录保留
        self.assertEqual(len(panel.amendments), 1)
        amendment = panel.amendments[0]
        self.assertEqual(amendment.issued_revision, version.revision)
        self.assertEqual(amendment.result_id, "r-t-late")
        self.assertEqual(amendment.result_sha256, receipt.result_sha256)
        self.assertEqual(len(panel.receipts), 4)
        self.assertEqual(panel.receipts[-1].disposition, "amendment")

    def test_result_not_in_dependency_set_is_rejected(self):
        # 开立一个只依赖形态学和毒素的结论
        self.registry.open_conclusion("C2", "INC2", ["morphology", "toxin"])
        with self.assertRaises(WorkflowConflict) as ctx:
            self.registry.record_result("INC2", result("r-g", "molecular"))
        self.assertEqual(ctx.exception.problems[0].code, "not_dependent")

    def test_duplicate_result_is_idempotent_with_receipt(self):
        data = result("r-m", "morphology")
        d1, r1 = self.registry.record_result("INC1", data)
        event_count = len(self.registry.events_for_replay())
        d2, r2 = self.registry.record_result("INC1", dict(data))
        self.assertEqual((d1, d2), ("draft_updated", "duplicate"))
        self.assertEqual(r2.result_sha256, r1.result_sha256)
        # 重复不产生新的领域事件，但保留一张 duplicate 回执
        self.assertEqual(len(self.registry.events_for_replay()), event_count)
        panel = self.registry.conclusions["INC1"]
        self.assertEqual(panel.receipts[-1].disposition, "duplicate")
        self.assertEqual(panel.draft_revision, 1)

    def test_result_id_reused_with_different_content_rejected(self):
        self.registry.record_result("INC1", result("r-m", "morphology", payload={"a": 1}))
        with self.assertRaises(WorkflowConflict) as ctx:
            self.registry.record_result(
                "INC1", result("r-m", "morphology", payload={"a": 2}))
        self.assertEqual(ctx.exception.problems[0].code, "result_id_conflict")

    def test_bad_result_shape_and_time_rejected(self):
        bad = result("r-x", "morphology")
        bad["received_at"] = "2026-09-20 11:00"
        with self.assertRaises(WorkflowConflict) as ctx:
            self.registry.record_result("INC1", bad)
        self.assertEqual(ctx.exception.problems[0].code, "invalid_time")
        with self.assertRaises(WorkflowConflict):
            self.registry.record_result("INC1", result("r-y", "spectrometry"))

    def test_replay_rebuilds_frozen_chain_and_amendments(self):
        three_results(self.registry)
        self.registry.issue("INC1", "2026-09-20T12:00:00+08:00")
        self.registry.record_result(
            "INC1", result("r-g2", "molecular", received_at="2026-09-20T16:00:00+08:00"))
        rebuilt = PanelRegistry.replay(self.registry.events_for_replay())
        before = self.registry.conclusions["INC1"]
        after = rebuilt.conclusions["INC1"]
        self.assertEqual(after.current_version.content_sha256,
                         before.current_version.content_sha256)
        self.assertEqual([a.amendment_id for a in after.amendments],
                         [a.amendment_id for a in before.amendments])
        self.assertEqual(
            [(r.result_id, r.disposition) for r in after.receipts],
            [(r.result_id, r.disposition) for r in before.receipts],
        )


if __name__ == "__main__":
    unittest.main()
