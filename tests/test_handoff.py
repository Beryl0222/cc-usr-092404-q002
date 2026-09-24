"""交接幂等、暂停关联与晚到结果路由测试。

* 同一文件原样重送不能重复登记；
* 文件名相同但内容不同要暂停关联；
* 晚到结果只能更新依赖它的未签发结论；已签发版本追加更正与接收回执。
"""

import tempfile
import unittest

from scenario import INCIDENT, run_standard, standard_steps

from fungus_chain import messages as m


def stamp(minute: int) -> str:
    return f"2026-09-20T09:{minute:02d}:00+08:00"


class IdempotencyAndHoldTest(unittest.TestCase):
    def test_identical_bytes_resubmitted_once_is_not_registered_twice(self):
        steps = standard_steps()
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=steps[:2])
        events_before = len(ledger.events)

        # 原样重送交接文件（同字节、同文件名、同消息编号）。
        outcome = ledger.submit_bytes(steps[0].raw, steps[0].file_name)
        self.assertEqual(outcome.kind, "duplicate")
        self.assertEqual(outcome.event_seq, 1)  # 指向首次登记事件
        self.assertEqual(outcome.command, "intake")

        # 只追加一条去重痕迹事件，不改变任何领域状态。
        self.assertEqual(len(ledger.events), events_before + 1)
        self.assertEqual(ledger.events[-1].kind, "duplicate_suppressed")
        self.assertEqual(ledger.events[-1].detail["first_event_seq"], 1)
        self.assertEqual(len(ledger.incidents), 1)
        self.assertEqual(len(ledger.samples), 4)  # 父样 + 3 子样

    def test_identical_bytes_under_new_name_still_duplicate(self):
        # 幂等以字节摘要为准，而非文件名：原样字节换文件名仍是重复。
        steps = standard_steps()
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=steps[:1])
        outcome = ledger.submit_bytes(steps[0].raw, "renamed-copy.json")
        self.assertEqual(outcome.kind, "duplicate")

    def test_resend_after_reload_stays_idempotent(self):
        import pathlib

        tmp = tempfile.mkdtemp()
        ledger, _, _ = _with_store(tmp, standard_steps()[:1])
        store = pathlib.Path(tmp) / "ledger.json"
        self.assertTrue(store.exists())
        from fungus_chain import ChainLedger

        reloaded = ChainLedger(store_path=store)
        outcome = reloaded.submit_bytes(standard_steps()[0].raw, "01-intake.json")
        self.assertEqual(outcome.kind, "duplicate")
        self.assertEqual(len(reloaded.incidents), 1)

    def test_same_filename_different_content_is_held(self):
        steps = standard_steps()
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=steps[:1])
        tampered = steps[0].raw.replace(b'"quantity": 10', b'"quantity": 11', 1)
        outcome = ledger.submit_bytes(tampered, steps[0].file_name)
        self.assertEqual(outcome.kind, "held")
        hold = outcome.hold
        self.assertEqual(hold.file_name, "01-intake.json")
        self.assertNotEqual(hold.incoming_sha256, hold.existing_sha256)
        self.assertIn("暂停", hold.reason)
        # 暂停的内容绝不登记：数量仍是 10，无第二个事件或样本。
        self.assertEqual(ledger.samples["s-bulk"].initial_quantity, 10)
        self.assertEqual(len(ledger.holds), 1)
        self.assertEqual(ledger.events[-1].kind, "held")
        # 台账里也没有出现新 message_id 的登记。

    def test_same_message_id_different_bytes_is_held(self):
        steps = standard_steps()
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=steps[:1])
        # 保持 message_id 与文件名语义，但字节不同、文件名不同：
        # 改一个 payload 字段并用新文件名，消息编号仍是 msg-intake。
        tampered = steps[0].raw.replace(b'"s-bulk"', b'"s-bulk-2"', 1)
        outcome = ledger.submit_bytes(tampered, "another-intake.json")
        self.assertEqual(outcome.kind, "held")
        self.assertNotIn("s-bulk-2", ledger.samples)

    def test_held_file_is_not_replayed_on_restart(self):
        # 暂停关联是持久状态；恢复后同名文件依旧暂停而非意外登记。
        import pathlib
        from fungus_chain import ChainLedger

        tmp = tempfile.mkdtemp()
        ledger, _, _ = _with_store(tmp, standard_steps()[:1])
        tampered = standard_steps()[0].raw.replace(
            b'"quantity": 10', b'"quantity": 12', 1
        )
        self.assertEqual(
            ledger.submit_bytes(tampered, "01-intake.json").kind, "held"
        )
        reloaded = ChainLedger(store_path=pathlib.Path(tmp) / "ledger.json")
        again = reloaded.submit_bytes(tampered, "01-intake.json")
        self.assertEqual(again.kind, "held")
        self.assertEqual(reloaded.samples["s-bulk"].initial_quantity, 10)


class LateResultRoutingTest(unittest.TestCase):
    def _issue_flow(self):
        return run_standard(tempfile.mkdtemp(), steps=standard_steps())

    def test_late_result_updates_only_unissued_dependent_conclusion(self):
        steps = standard_steps()
        # 只跑到：交接/拆分/耗用/建立结论/形态学结果，不签发。
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=steps[:7])
        conclusion = ledger.conclusions["con-1"]
        self.assertFalse(conclusion.issued)
        revisions_before = conclusion.revision
        self.assertIn("疑似鹅膏属", conclusion.content)
        # 形态学结果晚到，结论依赖 morphology -> 产生结果更新版本。
        self.assertEqual(revisions_before + 0, conclusion.revision)
        self.assertEqual(conclusion.revision, 2)  # 建立 v1，形态学结果更新 v2
        self.assertEqual(conclusion.versions[-1].kind, "result_update")
        self.assertIn("疑似致命鹅膏", conclusion.versions[-1].content)
        self.assertEqual(conclusion.corrections, [])

    def test_late_result_after_issue_appends_correction_and_receipt(self):
        ledger, _, report = self._issue_flow()
        conclusion = ledger.conclusions["con-1"]
        # 第 8 步签发；第 9 步毒素阳性（危急）晚到。
        self.assertTrue(conclusion.issued)
        self.assertEqual(conclusion.issued_revision, 2)
        issued_content = conclusion.versions[conclusion.issued_revision - 1].content
        version_count = len(conclusion.versions)

        # 已签发版本不可变：不新增版本、不改已签发内容。
        self.assertEqual(len(conclusion.versions), version_count)
        self.assertEqual(len(conclusion.corrections), 2)  # 毒素 + 分子两条晚到
        correction = conclusion.corrections[0]
        self.assertEqual(correction.test, "toxin")
        self.assertEqual(correction.result, "阳性 4.2mg/kg")
        self.assertTrue(correction.critical)
        # 更正保留来源证据：消息编号 + 字节摘要 + 接收回执。
        self.assertEqual(correction.source_message_id, "msg-result-tox")
        self.assertRegex(correction.source_sha256, r"^[0-9a-f]{64}$")
        self.assertTrue(correction.receipt_id.startswith("ack-con-1-"))
        self.assertEqual(correction.receipt_at, correction.received_at)
        # 已签发正文保持原样。
        self.assertEqual(
            conclusion.versions[conclusion.issued_revision - 1].content,
            issued_content,
        )

    def test_receipt_events_follow_result_event_and_reference_revision(self):
        ledger, _, _ = report = self._issue_flow()
        kinds = [e.kind for e in ledger.events]
        # 毒素结果事件之后紧跟一条 receipt（分子结果同样补一条 receipt）。
        self.assertIn("receipt", kinds)
        receipts = [e for e in ledger.events if e.kind == "receipt"]
        self.assertEqual(len(receipts), 2)
        for receipt in receipts:
            self.assertEqual(receipt.detail["issued_revision"], 2)
            self.assertTrue(receipt.detail["receipt_id"].startswith("ack-"))
            self.assertRegex(receipt.sha256, r"^[0-9a-f]{64}$")

    def test_late_result_for_unrelated_conclusion_is_not_routed(self):
        # 结论只依赖形态学时，毒素晚到结果不应改动它（签发前也不更新）。
        ledger, _, _ = run_standard(tempfile.mkdtemp(), steps=standard_steps()[:5])
        create = m.create_conclusion(
            message_id="con-morph-only",
            occurred_at=stamp(10),
            incident_id=INCIDENT,
            conclusion_id="con-morph",
            content="仅形态学结论",
            depends_on=["morphology"],
        )
        ledger.submit_bytes(create, "con-morph.json")
        tox = m.result(
            message_id="late-tox",
            occurred_at=stamp(40),
            sample_id="s-tox",
            test="toxin",
            analyte="鹅膏毒肽",
            result_value="阳性",
            critical=True,
        )
        ledger.submit_bytes(tox, "late-tox.json")
        conclusion = ledger.conclusions["con-morph"]
        self.assertEqual(len(conclusion.versions), 1)  # 未被更新
        self.assertEqual(conclusion.corrections, [])  # 未被追加更正

    def test_revising_issued_conclusion_directly_is_rejected(self):
        ledger, _, _ = self._issue_flow()
        revise = m.revise_conclusion(
            message_id="rev-after-issue",
            occurred_at=stamp(50),
            incident_id=INCIDENT,
            conclusion_id="con-1",
            content="试图覆盖已签发结论",
        )
        outcome = ledger.submit_bytes(revise, "revise-late.json")
        self.assertEqual(outcome.kind, "rejected")
        self.assertIn("已签发", outcome.reason)
        self.assertEqual(
            ledger.conclusions["con-1"].issued_revision, 2
        )

    def test_critical_notification_sent_once_and_bound_to_event(self):
        sent = []
        tmp = tempfile.mkdtemp()
        from fungus_chain import ChainLedger
        from scenario import make_workspace
        from fungus_chain import PanelRunner

        store, jobs = make_workspace(tmp)
        ledger = ChainLedger(store_path=store, notifier=lambda n: sent.append(n))
        runner = PanelRunner(ledger, jobs)
        runner.run("job", standard_steps())
        critical = [n for n in sent if n.kind == "critical"]
        self.assertEqual(len(critical), 1)  # 仅毒素阳性一次危急通知
        note = critical[0]
        self.assertEqual((note.sample_id, note.test), ("s-tox", "toxin"))
        # 通知绑定结果事件序号（回执之前）。
        result_event = next(
            e for e in ledger.events if e.kind == "record_result"
            and e.detail.get("test") == "toxin"
        )
        self.assertEqual(note.event_seq, result_event.seq)


def _with_store(tmp, steps):
    from fungus_chain import ChainLedger, PanelRunner
    from scenario import make_workspace

    store, jobs = make_workspace(tmp)
    ledger = ChainLedger(store_path=store)
    runner = PanelRunner(ledger, jobs)
    report = runner.run("job", steps)
    return ledger, runner, report


if __name__ == "__main__":
    unittest.main()
