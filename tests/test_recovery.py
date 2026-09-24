"""服务中断恢复测试与最终状态呈现。

服务中断后继续未完成联检：从头重放同一批原始字节，已应用步骤幂等跳过，
不得再次消耗样本或重复发出危急通知。
"""

import tempfile
import unittest
from pathlib import Path

from scenario import INCIDENT, make_workspace, standard_steps

from fungus_chain import ChainLedger, PanelRunner, ServiceInterrupted


class RecoveryTest(unittest.TestCase):
    def _open(self, tmp: str, notifier=None):
        store, jobs = make_workspace(tmp)
        ledger = ChainLedger(store_path=store, notifier=notifier)
        runner = PanelRunner(ledger, jobs)
        return store, jobs, ledger, runner

    def test_interrupted_run_then_resume_does_not_double_consume(self):
        tmp = tempfile.mkdtemp()
        steps = standard_steps()

        # 第一次运行：在第 5 个首次应用步骤（分子耗用）之后中断。
        _, jobs, ledger1, runner1 = self._open(tmp)
        runner1.fail_after = 5
        with self.assertRaises(ServiceInterrupted):
            runner1.run("job", steps)
        self.assertEqual(len(ledger1.events), 5)
        consumed_after_crash = {
            sid: dict(s.consumed_for) for sid, s in ledger1.samples.items()
        }

        # 模拟服务重启：从磁盘新建台账与执行器，不再注入故障。
        _, _, ledger2, runner2 = self._open(tmp)
        report = runner2.run("job", steps)

        # 前 5 步原样重放 -> 全部幂等；后 5 步本次应用。
        self.assertEqual([s.kind for s in report.steps[:5]], ["duplicate"] * 5)
        self.assertEqual([s.kind for s in report.steps[5:]], ["applied"] * 5)
        # 幂等结果指回首次登记事件序号。
        self.assertEqual(report.steps[0].event_seq, 1)

        # 样本没有被第二次消耗：耗用量与崩溃瞬间一致，余额守恒。
        for sid, consumed in consumed_after_crash.items():
            self.assertEqual(dict(ledger2.samples[sid].consumed_for), consumed)
        balance = ledger2.mass_balance("s-bulk")
        self.assertEqual(balance["consumed_total"], 6)  # 三子样各 2g，仅一次
        self.assertEqual(balance["remaining_total"], 4)
        self.assertEqual(balance["difference"], 0)
        ledger2.assert_balanced()

    def test_resume_uses_original_bytes_from_job_dir(self):
        tmp = tempfile.mkdtemp()
        steps = standard_steps()
        _, jobs, ledger1, runner1 = self._open(tmp)
        runner1.fail_after = 2
        with self.assertRaises(ServiceInterrupted):
            runner1.run("job", steps)

        # 作业目录保留了首次提交的原始字节；与内存步骤逐字节一致。
        first_file = Path(jobs) / steps[0].file_name
        self.assertEqual(first_file.read_bytes(), steps[0].raw)

        _, _, ledger2, runner2 = self._open(tmp)
        report = runner2.run("job", steps)
        # 重放识别为同一字节：重复事件记录首次摘要，而非新登记。
        dup_events = [e for e in ledger2.events if e.kind == "duplicate_suppressed"]
        self.assertEqual(len(dup_events), 2)
        self.assertEqual(dup_events[0].detail["first_event_seq"], 1)

    def test_critical_notification_not_resent_on_resume(self):
        tmp = tempfile.mkdtemp()
        steps = standard_steps()

        # 第一次运行跑到第 9 步（危急的毒素晚到结果）之后崩溃。
        _, _, ledger1, runner1 = self._open(tmp, notifier=lambda n: None)
        runner1.fail_after = 9
        with self.assertRaises(ServiceInterrupted):
            runner1.run("job", steps)
        persisted = [
            n for n in ledger1.notifications if n.kind == "critical"
        ]
        self.assertEqual(len(persisted), 1)
        first_note = persisted[0]

        # 重启续跑：新进程的外发回调只应看到 0 条通知（第 10 步分子非危急）。
        sent_after_restart = []
        _, _, ledger2, runner2 = self._open(
            tmp, notifier=lambda n: sent_after_restart.append(n)
        )
        report = runner2.run("job", steps)
        self.assertEqual([s.kind for s in report.steps[:9]], ["duplicate"] * 9)
        self.assertEqual(report.steps[9].kind, "applied")
        self.assertEqual(sent_after_restart, [])

        # 持久化的危急通知仍然只有最初一条，去重键与事件序号稳定。
        critical = [n for n in ledger2.notifications if n.kind == "critical"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].dedupe_key, first_note.dedupe_key)
        self.assertEqual(critical[0].event_seq, first_note.event_seq)

        # 即便再次完整重放一遍，外发通知依然为零。
        sent_on_replay = []
        ledger2._notifier = lambda n: sent_on_replay.append(n)
        runner2.run("job", steps)
        self.assertEqual(sent_on_replay, [])
        self.assertEqual(
            len([n for n in ledger2.notifications if n.kind == "critical"]), 1
        )

    def test_full_replay_without_restart_is_also_idempotent(self):
        # 不重启、同一台账直接重放：幂等不依赖进程边界。
        tmp = tempfile.mkdtemp()
        steps = standard_steps()
        _, _, ledger, runner = self._open(tmp)
        first = runner.run("job", steps)
        second = runner.run("job", steps)
        self.assertTrue(first.all_committed())
        self.assertEqual(len(second.applied_now), 0)
        self.assertEqual(len(second.duplicates), len(steps))
        self.assertEqual(len(ledger.incidents), 1)
        ledger.assert_balanced()

    def test_restarted_ledger_state_is_complete_and_balanced(self):
        tmp = tempfile.mkdtemp()
        steps = standard_steps()
        store, _, ledger, runner = self._open(tmp)
        runner.run("job", steps)

        reloaded = ChainLedger(store_path=store)
        reloaded.assert_balanced()
        self.assertEqual(len(reloaded.samples), 4)
        self.assertTrue(reloaded.conclusions["con-1"].issued)
        self.assertEqual(len(reloaded.conclusions["con-1"].corrections), 2)
        # 事件流、通知、保管链序号在恢复后连续可用。
        seqs = [e.seq for e in reloaded.events]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


class FinalStatePresentationTest(unittest.TestCase):
    """以一次完整事件呈现最终状态：隔离、守恒、签发结论与更正回执并存。"""

    def test_final_state_after_mixed_inputs_and_recovery(self):
        tmp = tempfile.mkdtemp()
        store, jobs = make_workspace(tmp)
        ledger = ChainLedger(store_path=store)

        # 先混入两份问题文件：重复键、尾随内容，均隔离不登记。
        dup_key = (
            b'{"schema_version":1,"message_id":"d2","message_id":"d3",'
            b'"command":"consume","occurred_at":"2026-09-20T09:00:00+08:00",'
            b'"payload":{"sample_id":"s","test":"toxin","quantity":1}}'
        )
        trailing = (
            b'{"schema_version":1,"message_id":"t1","command":"consume",'
            b'"occurred_at":"2026-09-20T09:00:00+08:00",'
            b'"payload":{"sample_id":"s","test":"toxin","quantity":1}} | garbage'
        )
        ledger.submit_bytes(dup_key, "mixed-dup.json")
        ledger.submit_bytes(trailing, "mixed-tail.json")

        # 联检主体跑到第 8 步（签发）后中断，再恢复补齐。
        runner = PanelRunner(ledger, jobs, fail_after=8)
        with self.assertRaises(ServiceInterrupted):
            runner.run("job", standard_steps())
        runner2 = PanelRunner(
            ChainLedger(store_path=store), jobs
        )
        report = runner2.run("job", standard_steps())
        final = runner2.ledger

        # 1) 两份问题文件保留隔离记录：字节摘要 + 可定位问题；
        #    这里的 final 台账是服务重启后从磁盘重载的，验证摘要字节保真。
        self.assertEqual(len(final.quarantines), 2)
        codes = {i.code for q in final.quarantines for i in q.issues}
        self.assertEqual(codes, {"duplicate_key", "trailing_content"})
        for q, raw in zip(final.quarantines, [dup_key, trailing]):
            self.assertRegex(q.sha256, r"^[0-9a-f]{64}$")
            self.assertTrue(q.issues[0].line)
            self.assertTrue(q.raw_excerpt.startswith(b"{"))
            self.assertEqual(q.raw_excerpt, raw[: len(q.raw_excerpt)])

        # 2) 分样树守恒。
        balance = final.mass_balance("s-bulk")
        self.assertEqual(
            balance,
            {
                "root_sample_id": "s-bulk",
                "initial_quantity": 10,
                "remaining_total": 4,
                "consumed_total": 6,
                "difference": 0,
            },
        )

        # 3) 结论已签发 v2，两条晚到结果只追加更正与回执，版本不增长。
        conclusion = final.conclusions["con-1"]
        self.assertTrue(conclusion.issued)
        self.assertEqual(conclusion.issued_revision, 2)
        self.assertEqual(len(conclusion.versions), 2)
        self.assertEqual([c.test for c in conclusion.corrections], ["toxin", "molecular"])
        self.assertTrue(
            all(c.receipt_id.startswith("ack-") for c in conclusion.corrections)
        )

        # 4) 续跑步骤全部已提交（前 8 步幂等、后 2 步应用），无暂停/拒收。
        self.assertEqual([s.kind for s in report.steps[:8]], ["duplicate"] * 8)
        self.assertEqual([s.kind for s in report.steps[8:]], ["applied"] * 2)
        self.assertTrue(report.all_committed())

        # 5) 危急通知恰好一条。
        self.assertEqual(
            len([n for n in final.notifications if n.kind == "critical"]), 1
        )

        # 6) 事件所属事件编号唯一，保管链可完整回放审计。
        applied = [e for e in final.events if e.kind in {
            "intake", "split", "consume", "record_result",
            "create_conclusion", "issue_conclusion",
        }]
        # 10 条业务命令各恰好一条生效事件。
        self.assertEqual(len(applied), 10)


if __name__ == "__main__":
    unittest.main()
