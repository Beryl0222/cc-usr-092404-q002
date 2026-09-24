"""联检结论与晚到结果规则。

规则来自交接约定：

* 一份误食事件的联检结论依赖固定的检测集合（形态学 / 毒素 / 分子）；
* 结果晚到时，**只能更新依赖它、且尚未签发**的结论草稿；
* 一旦版本已向临床签发，其内容即冻结，后续结果只能以**更正**形式追加，
  同时保留**接收回执**，历史版本不可覆盖；
* 不属于任何结论依赖集合的检测结果拒绝登记。

所有写入按 ``result_id`` / ``conclusion_id`` 幂等，原样重放不产生新版本。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .errors import EvidenceError, Problem, WorkflowConflict
from .timeutil import parse_instant

_ASSAYS = ("morphology", "toxin", "molecular")


def canonical_digest(payload: Any) -> str:
    """对结构化内容计算稳定摘要，用作签发版本/结果的完整性指纹。"""

    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ResultRecord:
    result_id: str
    assay: str
    sample_id: str
    payload: dict[str, Any]
    occurred_at: str
    received_at: str

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "result_id": self.result_id,
                "assay": self.assay,
                "sample_id": self.sample_id,
                "payload": self.payload,
                "occurred_at": self.occurred_at,
            }
        )


@dataclass(frozen=True)
class Receipt:
    """检测结果接收回执：证明某结果在某时刻到达并归入何处。"""

    result_id: str
    assay: str
    sample_id: str
    result_sha256: str
    received_at: str
    disposition: str  # draft_updated | amendment | duplicate
    conclusion_id: str
    amendment_id: str | None = None


@dataclass(frozen=True)
class IssuedVersion:
    revision: int
    issued_at: str
    content_sha256: str
    depended_assays: tuple[str, ...]
    result_ids: tuple[str, ...]
    summary: str
    # 签发快照不可变
    results: dict[str, str]


@dataclass(frozen=True)
class Amendment:
    """对已签发版本的追加更正，不修改原版本任何字节。"""

    amendment_id: str
    conclusion_id: str
    issued_revision: int
    assay: str
    result_id: str
    result_sha256: str
    received_at: str
    note: str
    content_sha256: str


@dataclass
class PanelConclusion:
    conclusion_id: str
    incident_id: str
    depended_assays: tuple[str, ...]
    results: dict[str, ResultRecord] = field(default_factory=dict)  # assay -> latest
    result_index: dict[str, ResultRecord] = field(default_factory=dict)  # result_id
    draft_revision: int = 0
    draft_updated_at: str | None = None
    issued: list[IssuedVersion] = field(default_factory=list)
    amendments: list[Amendment] = field(default_factory=list)
    receipts: list[Receipt] = field(default_factory=list)

    # ------------------------------------------------------------------ 状态

    @property
    def is_issued(self) -> bool:
        return bool(self.issued)

    @property
    def current_version(self) -> IssuedVersion | None:
        return self.issued[-1] if self.issued else None

    def missing_assays(self) -> list[str]:
        return [a for a in self.depended_assays if a not in self.results]

    def draft_snapshot(self) -> dict[str, Any]:
        return {
            "conclusion_id": self.conclusion_id,
            "incident_id": self.incident_id,
            "depended_assays": list(self.depended_assays),
            "draft_revision": self.draft_revision,
            "results": {a: self.results[a].result_id for a in sorted(self.results)},
            "result_digests": {a: self.results[a].digest for a in sorted(self.results)},
        }

    # ------------------------------------------------------------------ 写入

    def record_result(self, result: ResultRecord) -> tuple[str, Receipt]:
        """登记一个检测结果。

        返回 (处置方式, 回执)。处置方式为 draft_updated / amendment / duplicate。
        """

        if result.assay not in self.depended_assays:
            raise WorkflowConflict([Problem(
                "not_dependent",
                f"结论 {self.conclusion_id} 不依赖 {result.assay} 检测，"
                "晚到结果只能归入依赖它的结论",
                pointer="/assay",
            )])
        prior = self.result_index.get(result.result_id)
        if prior is not None:
            if prior.digest == result.digest:
                # 原样重送：保留一张 duplicate 回执，不再修改草稿/版本。
                receipt = self._receipt(result, "duplicate", None)
                self.receipts.append(receipt)
                return "duplicate", receipt
            raise WorkflowConflict([Problem(
                "result_id_conflict",
                f"result_id {result.result_id!r} 已用于不同内容的结果，禁止复用标识",
                pointer="/result_id",
            )])

        if not self.is_issued:
            # 未签发：直接并入草稿。同 assay 的新结果覆盖草稿取值（草稿可修订），
            # 但每个 result_id 都有回执可追溯。
            self.results[result.assay] = result
            self.result_index[result.result_id] = result
            self.draft_revision += 1
            self.draft_updated_at = result.received_at
            receipt = self._receipt(result, "draft_updated", None)
            self.receipts.append(receipt)
            return "draft_updated", receipt

        # 已签发：原版本冻结，只能追加更正与回执。
        version = self.current_version
        amendment_id = f"{self.conclusion_id}-a{len(self.amendments) + 1}"
        content = {
            "amendment_id": amendment_id,
            "conclusion_id": self.conclusion_id,
            "issued_revision": version.revision,
            "result_id": result.result_id,
            "result_sha256": result.digest,
        }
        amendment = Amendment(
            amendment_id=amendment_id,
            conclusion_id=self.conclusion_id,
            issued_revision=version.revision,
            assay=result.assay,
            result_id=result.result_id,
            result_sha256=result.digest,
            received_at=result.received_at,
            note=(
                f"{result.assay} 检测结果晚到（result_id={result.result_id}），"
                f"已签发版本 revision={version.revision} 保持不变，本更正随结论追加"
            ),
            content_sha256=canonical_digest(content),
        )
        self.result_index[result.result_id] = result
        self.amendments.append(amendment)
        receipt = self._receipt(result, "amendment", amendment_id)
        self.receipts.append(receipt)
        return "amendment", receipt

    def issue(self, issued_at: str, summary: str = "") -> IssuedVersion:
        if self.is_issued:
            raise WorkflowConflict([Problem(
                "already_issued",
                f"结论 {self.conclusion_id} 已有签发版本；新版本须基于更正重新走签发流程",
            )])
        missing = self.missing_assays()
        if missing:
            raise WorkflowConflict([Problem(
                "incomplete_panel",
                f"联检结论依赖的检测尚缺 {missing}，不允许向临床签发",
            )])
        snapshot = {a: self.results[a].result_id for a in self.depended_assays}
        version = IssuedVersion(
            revision=1,
            issued_at=issued_at,
            content_sha256=canonical_digest(
                {
                    "conclusion_id": self.conclusion_id,
                    "depended_assays": list(self.depended_assays),
                    "results": {a: self.results[a].digest for a in self.depended_assays},
                }
            ),
            depended_assays=tuple(self.depended_assays),
            result_ids=tuple(self.results[a].result_id for a in self.depended_assays),
            summary=summary,
            results=snapshot,
        )
        self.issued.append(version)
        return version

    def _receipt(self, result: ResultRecord, disposition: str,
                 amendment_id: str | None) -> Receipt:
        return Receipt(
            result_id=result.result_id,
            assay=result.assay,
            sample_id=result.sample_id,
            result_sha256=result.digest,
            received_at=result.received_at,
            disposition=disposition,
            conclusion_id=self.conclusion_id,
            amendment_id=amendment_id,
        )


class PanelRegistry:
    """incident_id -> PanelConclusion 的注册表，事件式重放。"""

    def __init__(self) -> None:
        self.conclusions: dict[str, PanelConclusion] = {}
        self._events: list[dict[str, Any]] = []

    def open_conclusion(
        self, conclusion_id: str, incident_id: str, depended_assays: list[str] | tuple[str, ...]
    ) -> PanelConclusion:
        if conclusion_id in {c.conclusion_id for c in self.conclusions.values()}:
            raise WorkflowConflict([Problem(
                "duplicate_conclusion", f"结论 {conclusion_id!r} 已开立", pointer="/conclusion_id",
            )])
        bad = [a for a in depended_assays if a not in _ASSAYS]
        if bad or not depended_assays:
            raise WorkflowConflict([Problem(
                "invalid_value",
                f"depended_assays 必须是 {list(_ASSAYS)} 的非空子集，得到 {list(depended_assays)!r}",
                pointer="/depended_assays",
            )])
        if len(set(depended_assays)) != len(depended_assays):
            raise WorkflowConflict([Problem(
                "invalid_value", "depended_assays 存在重复检测项", pointer="/depended_assays",
            )])
        if incident_id in self.conclusions:
            raise WorkflowConflict([Problem(
                "duplicate_conclusion",
                f"事件 {incident_id!r} 已有联检结论，一个事件只维护一条结论链",
                pointer="/incident_id",
            )])
        panel = PanelConclusion(
            conclusion_id=conclusion_id,
            incident_id=incident_id,
            depended_assays=tuple(depended_assays),
        )
        self.conclusions[incident_id] = panel
        self._events.append({
            "type": "open_conclusion",
            "conclusion_id": conclusion_id,
            "incident_id": incident_id,
            "depended_assays": list(depended_assays),
        })
        return panel

    def record_result(self, incident_id: str, data: dict[str, Any]) -> tuple[str, Receipt]:
        panel = self._require(incident_id)
        self._validate_result_data(data)
        result = ResultRecord(
            result_id=data["result_id"],
            assay=data["assay"],
            sample_id=data["sample_id"],
            payload=data.get("payload", {}),
            occurred_at=data["occurred_at"],
            received_at=data["received_at"],
        )
        disposition, receipt = panel.record_result(result)
        if disposition != "duplicate":
            self._events.append({"type": "record_result", "incident_id": incident_id, "data": data})
        return disposition, receipt

    @staticmethod
    def _validate_result_data(data: Any) -> None:
        problems: list[Problem] = []
        if not isinstance(data, dict):
            raise WorkflowConflict([Problem("type_mismatch", "结果必须是对象", pointer="/")])
        for key in ("result_id", "assay", "sample_id", "occurred_at", "received_at"):
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                problems.append(Problem("missing_field",
                                        f"结果缺少非空字符串字段 {key!r}", pointer=f"/{key}"))
        if isinstance(data.get("assay"), str) and data["assay"] not in _ASSAYS:
            problems.append(Problem("invalid_value",
                                    f"assay 必须是 {list(_ASSAYS)} 之一", pointer="/assay"))
        if "payload" in data and not isinstance(data["payload"], dict):
            problems.append(Problem("type_mismatch", "payload 必须是对象", pointer="/payload"))
        for key in ("occurred_at", "received_at"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                try:
                    parse_instant(value)
                except ValueError as exc:
                    problems.append(Problem("invalid_time",
                                            f"{key} 非法: {exc}", pointer=f"/{key}"))
        if problems:
            raise WorkflowConflict(problems)

    def issue(self, incident_id: str, issued_at: str, summary: str = "") -> IssuedVersion:
        panel = self._require(incident_id)
        version = panel.issue(issued_at, summary)
        self._events.append({
            "type": "issue", "incident_id": incident_id,
            "issued_at": issued_at, "summary": summary,
        })
        return version

    def _require(self, incident_id: str) -> PanelConclusion:
        panel = self.conclusions.get(incident_id)
        if panel is None:
            raise WorkflowConflict([Problem(
                "unknown_incident", f"事件 {incident_id!r} 尚未开立联检结论", pointer="/incident_id",
            )])
        return panel

    def events_for_replay(self) -> list[dict[str, Any]]:
        return list(self._events)

    @classmethod
    def replay(cls, events: list[dict[str, Any]]) -> "PanelRegistry":
        registry = cls()
        for ev in events:
            kind = ev["type"]
            if kind == "open_conclusion":
                registry.open_conclusion(
                    ev["conclusion_id"], ev["incident_id"], ev["depended_assays"]
                )
            elif kind == "record_result":
                registry.record_result(ev["incident_id"], ev["data"])
            elif kind == "issue":
                registry.issue(ev["incident_id"], ev["issued_at"], ev.get("summary", ""))
            else:
                raise EvidenceError([Problem("invalid_value", f"未知结论事件类型 {kind!r}")])
        return registry
