"""测试共用：一次误食事件联检的标准命令序列与临时台账工厂。"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fungus_chain import ChainLedger, PanelRunner, Step, messages as m  # noqa: E402

INCIDENT = "inc-2026-0920"


def stamp(minute: int) -> str:
    return f"2026-09-20T09:{minute:02d}:00+08:00"


def standard_steps() -> list[Step]:
    """父样 10g 拆为形态/毒素/分子三个子样（各 3g，留 1g），全流程命令。"""
    return [
        Step(
            "01-intake.json",
            m.intake(
                message_id="msg-intake",
                occurred_at=stamp(0),
                incident_id=INCIDENT,
                samples=[
                    {
                        "sample_id": "s-bulk",
                        "specimen": "野生菌残体",
                        "tests": ["morphology", "toxin", "molecular"],
                        "quantity": 10,
                        "unit": "g",
                    }
                ],
            ),
        ),
        Step(
            "02-split.json",
            m.split(
                message_id="msg-split",
                occurred_at=stamp(2),
                parent_sample_id="s-bulk",
                children=[
                    {"sample_id": "s-morph", "quantity": 3, "tests": ["morphology"]},
                    {"sample_id": "s-tox", "quantity": 3, "tests": ["toxin"]},
                    {"sample_id": "s-mol", "quantity": 3, "tests": ["molecular"]},
                ],
                remaining_quantity=1,
            ),
        ),
        Step(
            "03-consume-morph.json",
            m.consume(
                message_id="msg-consume-morph",
                occurred_at=stamp(3),
                sample_id="s-morph",
                test="morphology",
                quantity=2,
            ),
        ),
        Step(
            "04-consume-tox.json",
            m.consume(
                message_id="msg-consume-tox",
                occurred_at=stamp(4),
                sample_id="s-tox",
                test="toxin",
                quantity=2,
            ),
        ),
        Step(
            "05-consume-mol.json",
            m.consume(
                message_id="msg-consume-mol",
                occurred_at=stamp(5),
                sample_id="s-mol",
                test="molecular",
                quantity=2,
            ),
        ),
        Step(
            "06-conclusion-draft.json",
            m.create_conclusion(
                message_id="msg-conclusion-create",
                occurred_at=stamp(10),
                incident_id=INCIDENT,
                conclusion_id="con-1",
                content="初步：形态学疑似鹅膏属，等待毒素与分子确认。",
                depends_on=["morphology", "toxin", "molecular"],
            ),
        ),
        Step(
            "07-result-morph.json",
            m.result(
                message_id="msg-result-morph",
                occurred_at=stamp(12),
                sample_id="s-morph",
                test="morphology",
                analyte="形态特征",
                result_value="疑似致命鹅膏",
                critical=False,
            ),
        ),
        Step(
            "08-conclusion-issue.json",
            m.issue_conclusion(
                message_id="msg-conclusion-issue",
                occurred_at=stamp(20),
                incident_id=INCIDENT,
                conclusion_id="con-1",
            ),
        ),
        Step(
            "09-result-toxin-late.json",
            m.result(
                message_id="msg-result-tox",
                occurred_at=stamp(40),
                sample_id="s-tox",
                test="toxin",
                analyte="α-鹅膏毒肽",
                result_value="阳性 4.2mg/kg",
                critical=True,
            ),
        ),
        Step(
            "10-result-mol-late.json",
            m.result(
                message_id="msg-result-mol",
                occurred_at=stamp(45),
                sample_id="s-mol",
                test="molecular",
                analyte="ITS 条码",
                result_value="与致命鹅膏同源",
                critical=False,
            ),
        ),
    ]


def make_workspace(tmp: str) -> tuple[Path, Path]:
    root = Path(tmp)
    return root / "ledger.json", root / "jobs"


def fresh_ledger(tmp: str, **kwargs) -> ChainLedger:
    store, _ = make_workspace(tmp)
    return ChainLedger(store_path=store, **kwargs)


def run_standard(tmp: str, *, fail_after=None, steps=None, notifier=None):
    store, jobs = make_workspace(tmp)
    ledger = ChainLedger(store_path=store, notifier=notifier)
    runner = PanelRunner(ledger, jobs, fail_after=fail_after)
    report = runner.run("job-inc-2026-0920", steps or standard_steps())
    return ledger, runner, report
