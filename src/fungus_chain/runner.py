"""联检流程执行器：把一次误食事件的联检编排为一串命令文件，并可恢复续跑。

续跑策略是**从头重放同一批原始字节**：台账以 SHA-256 幂等登记，已应用
的文件返回 :class:`SubmissionOutcome`（``kind == "duplicate"``）而不产生
任何领域效果。因此服务中断后继续未完成联检时：

* 已耗用样本不会被再次耗用（重复耗用命令被幂等挡在入口，业务层另有
  “同项目只能耗用一次”的双保险）；
* 危急通知只在结果版本首次入账时发出一次，重放不会二发；
* 未完成的步骤在恢复后继续提交。

为了让“原样重送”真实成立，执行器把每个步骤的字节落盘到作业目录，
恢复时直接读取原文件提交，而不是重新序列化。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .ledger import ChainLedger, SubmissionOutcome


class ServiceInterrupted(RuntimeError):
    """测试用故障注入：模拟服务在指定步骤应用后中断。"""


@dataclass(frozen=True)
class Step:
    file_name: str
    raw: bytes


@dataclass
class StepReport:
    index: int
    file_name: str
    kind: str
    event_seq: int | None
    command: str | None = None
    reason: str | None = None

    @property
    def was_applied_now(self) -> bool:
        return self.kind == "applied"


@dataclass
class RunReport:
    job_id: str
    steps: list[StepReport] = field(default_factory=list)

    @property
    def applied_now(self) -> list[StepReport]:
        return [s for s in self.steps if s.was_applied_now]

    @property
    def duplicates(self) -> list[StepReport]:
        return [s for s in self.steps if s.kind == "duplicate"]

    @property
    def blocked(self) -> list[StepReport]:
        return [s for s in self.steps if s.kind not in ("applied", "duplicate")]

    def all_committed(self) -> bool:
        return not self.blocked


class PanelRunner:
    def __init__(
        self,
        ledger: ChainLedger,
        job_dir: str | Path,
        *,
        fail_after: int | None = None,
    ) -> None:
        self.ledger = ledger
        self.job_dir = Path(job_dir)
        self.job_dir.mkdir(parents=True, exist_ok=True)
        # 在第 N 个“首次应用”步骤之后抛出 ServiceInterrupted；None 表示不注入。
        self.fail_after = fail_after

    def run(self, job_id: str, steps: list[Step]) -> RunReport:
        report = RunReport(job_id=job_id)
        applied_this_run = 0
        for index, step in enumerate(steps, start=1):
            # 恢复时优先复用已落盘的原始字节，保证与首次提交逐字节一致。
            path = self.job_dir / step.file_name
            if path.exists():
                persisted = path.read_bytes()
                if persisted != step.raw:
                    raise ValueError(
                        f"作业目录中 {step.file_name} 的字节与本次步骤不一致，"
                        "拒绝用新内容顶替已归档的原始证据"
                    )
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(step.raw)
            raw = path.read_bytes()

            outcome: SubmissionOutcome = self.ledger.submit_bytes(raw, step.file_name)
            if outcome.kind not in ("applied", "duplicate", "held", "quarantined", "rejected"):
                raise RuntimeError(f"未知提交结果 {outcome.kind}")
            report.steps.append(
                StepReport(
                    index=index,
                    file_name=step.file_name,
                    kind=outcome.kind,
                    event_seq=outcome.event_seq,
                    command=outcome.command,
                    reason=outcome.reason,
                )
            )
            if outcome.kind == "applied":
                applied_this_run += 1
                if self.fail_after is not None and applied_this_run == self.fail_after:
                    raise ServiceInterrupted(
                        f"服务在第 {index} 步（{step.file_name}）应用后中断"
                    )
        return report


__all__ = ["PanelRunner", "RunReport", "ServiceInterrupted", "Step", "StepReport"]
