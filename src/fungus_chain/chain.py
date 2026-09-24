"""样本保管链：交接、拆分、耗用、补样的数量守恒账本。

核心不变量（对每个样本实时成立）::

    初始接收量 + 累计补样量 == 累计耗用量 + 累计拆打量 + 当前结余量

跨样本视角，分样是家族内部转移：一次误食事件的家族总量满足::

    外部进入量（交接 + 补样） == 累计耗用量 + 当前结余总量

所有写操作由带 ``event_id`` 的事件驱动；同一 event_id 原样重放幂等，
同号不同载荷直接拒绝，防止重放过程中悄悄改写历史。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from .errors import ChainViolation, Problem
from .timeutil import parse_instant

_ASSAYS = ("morphology", "toxin", "molecular")


def _q(value: Any, pointer: str, problems: list[Problem], allow_zero: bool = False) -> Decimal | None:
    try:
        result = Decimal(str(value))
    except Exception:
        problems.append(Problem("invalid_value", f"数量无法解析: {value!r}", pointer=pointer))
        return None
    if not result.is_finite() or result < 0 or (result == 0 and not allow_zero):
        problems.append(Problem("invalid_value",
                                f"数量必须为{'非负' if allow_zero else '正'}数，得到 {value!r}",
                                pointer=pointer))
    return result


@dataclass
class SampleState:
    sample_id: str
    incident_id: str
    matrix: str
    unit: str
    received: Decimal = Decimal(0)
    replenished: Decimal = Decimal(0)
    consumed: Decimal = Decimal(0)
    split_out: Decimal = Decimal(0)
    custodian: str | None = None
    parents: dict[str, Decimal] = field(default_factory=dict)
    children: dict[str, Decimal] = field(default_factory=dict)

    @property
    def balance(self) -> Decimal:
        return self.received + self.replenished - self.consumed - self.split_out

    def snapshot(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "incident_id": self.incident_id,
            "matrix": self.matrix,
            "unit": self.unit,
            "received": str(self.received),
            "replenished": str(self.replenished),
            "consumed": str(self.consumed),
            "split_out": str(self.split_out),
            "balance": str(self.balance),
            "custodian": self.custodian,
            "parents": dict(self.parents),
            "children": dict(self.children),
        }


@dataclass(frozen=True)
class ChainEntry:
    seq: int
    event_id: str
    action: str
    occurred_at: str
    sample_id: str
    detail: dict[str, Any]
    balance_after: str
    custodian_after: str | None


class ChainLedger:
    def __init__(self) -> None:
        self.samples: dict[str, SampleState] = {}
        self.entries: list[ChainEntry] = []
        self._events: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ 应用

    def apply(self, event: dict[str, Any]) -> ChainEntry:
        problems = self._validate_basic(event)
        if problems:
            raise ChainViolation(problems)
        event_id = event["event_id"]
        if event_id in self._events:
            if self._events[event_id] == event:
                # 同一事件原样重送：幂等返回，不产生新的耗用或拆分。
                return next(e for e in self.entries if e.event_id == event_id)
            raise ChainViolation([Problem(
                "event_id_conflict",
                f"event_id {event_id!r} 已用于不同载荷的事件，禁止复用",
                pointer="/event_id",
            )])
        action = event["action"]
        handler = {
            "handoff": self._apply_handoff,
            "split": self._apply_split,
            "consume": self._apply_consume,
            "replenish": self._apply_replenish,
        }.get(action)
        if handler is None:
            raise ChainViolation([Problem(
                "invalid_value", f"未知保管链动作 {action!r}", pointer="/action",
            )])
        entry = handler(event)
        self._events[event_id] = event
        self.entries.append(entry)
        return entry

    def apply_many(self, events: list[dict[str, Any]]) -> list[ChainEntry]:
        out: list[ChainEntry] = []
        for event in events:
            out.append(self.apply(event))
        return out

    # ------------------------------------------------------------- 各动作实现

    def _apply_handoff(self, ev: dict[str, Any]) -> ChainEntry:
        sample_id = ev["sample_id"]
        qty = Decimal(str(ev["quantity"]))
        existing = self.samples.get(sample_id)
        if existing is None:
            if qty <= 0:
                raise ChainViolation([Problem(
                    "invalid_value",
                    f"首次交接登记样本 {sample_id} 的数量必须为正数，得到 {qty}",
                    pointer="/quantity",
                )])
            missing = [k for k in ("incident_id", "matrix", "unit") if not isinstance(ev.get(k), str) or not ev[k].strip()]
            if missing:
                raise ChainViolation([Problem(
                    "missing_field",
                    f"首次交接登记样本 {sample_id} 时缺少字段 {missing}", pointer="/",
                )])
            sample = SampleState(
                sample_id=sample_id,
                incident_id=ev["incident_id"],
                matrix=ev["matrix"],
                unit=ev["unit"],
                received=qty,
                custodian=ev["to_party"],
            )
            self.samples[sample_id] = sample
            detail = {"from_party": ev["from_party"], "to_party": ev["to_party"], "kind": "intake"}
        else:
            sample = existing
            if sample.unit and "unit" in ev and ev["unit"] != sample.unit:
                raise ChainViolation([Problem(
                    "unit_mismatch",
                    f"样本 {sample_id} 单位为 {sample.unit!r}，交接单使用 {ev['unit']!r}",
                    pointer="/unit",
                )])
            if sample.custodian != ev["from_party"]:
                raise ChainViolation([Problem(
                    "custody_gap",
                    f"样本 {sample_id} 当前保管方为 {sample.custodian!r}，"
                    f"交接单却声称从 {ev['from_party']!r} 处交出，保管链断裂",
                    pointer="/from_party",
                )])
            sample.custodian = ev["to_party"]
            detail = {"from_party": ev["from_party"], "to_party": ev["to_party"], "kind": "transfer"}
        return self._entry(ev, sample, detail)

    def _apply_split(self, ev: dict[str, Any]) -> ChainEntry:
        parent_id = ev["sample_id"]
        parent = self._require_sample(parent_id)
        qty = Decimal(str(ev["quantity"]))
        child_id = ev["child_sample_id"]
        if child_id in self.samples:
            raise ChainViolation([Problem(
                "duplicate_sample", f"子样 {child_id!r} 已存在，拆分会覆盖既有样本",
                pointer="/child_sample_id",
            )])
        if child_id == parent_id:
            raise ChainViolation([Problem(
                "invalid_value", "子样标识不能与父样相同", pointer="/child_sample_id",
            )])
        if parent.custodian != ev["from_party"]:
            raise ChainViolation([Problem(
                "custody_gap",
                f"父样 {parent_id} 当前保管方为 {parent.custodian!r}，"
                f"拆分单声称从 {ev['from_party']!r} 处取出",
                pointer="/from_party",
            )])
        if qty > parent.balance:
            raise ChainViolation([Problem(
                "conservation_violation",
                f"拆分量 {qty} 超过父样 {parent_id} 可拆分结余 {parent.balance}，"
                "父子数量守恒被破坏",
                pointer="/quantity",
            )])
        parent.split_out += qty
        child = SampleState(
            sample_id=child_id,
            incident_id=parent.incident_id,
            matrix=parent.matrix,
            unit=parent.unit,
            received=qty,
            custodian=ev["to_party"],
            parents={parent_id: qty},
        )
        self.samples[child_id] = child
        parent.children[child_id] = parent.children.get(child_id, Decimal(0)) + qty
        detail = {
            "from_party": ev["from_party"], "to_party": ev["to_party"],
            "kind": "split", "child_sample_id": child_id, "assay": ev.get("assay"),
        }
        return self._entry(ev, parent, detail)

    def _apply_consume(self, ev: dict[str, Any]) -> ChainEntry:
        sample = self._require_sample(ev["sample_id"])
        qty = Decimal(str(ev["quantity"]))
        if sample.custodian != ev["by_party"]:
            raise ChainViolation([Problem(
                "custody_gap",
                f"样本 {sample.sample_id} 由 {sample.custodian!r} 保管，"
                f"{ev['by_party']!r} 不能直接耗用",
                pointer="/by_party",
            )])
        if qty > sample.balance:
            raise ChainViolation([Problem(
                "conservation_violation",
                f"耗用量 {qty} 超过样本 {sample.sample_id} 结余 {sample.balance}，"
                "不允许出现负库存",
                pointer="/quantity",
            )])
        sample.consumed += qty
        detail = {"by_party": ev["by_party"], "kind": "consume", "assay": ev.get("assay")}
        return self._entry(ev, sample, detail)

    def _apply_replenish(self, ev: dict[str, Any]) -> ChainEntry:
        sample = self._require_sample(ev["sample_id"])
        qty = Decimal(str(ev["quantity"]))
        sample.replenished += qty
        detail = {"from_party": ev["from_party"], "kind": "replenish", "reason": ev.get("reason", "")}
        return self._entry(ev, sample, detail)

    # ------------------------------------------------------------- 守恒校验

    def family_report(self, sample_id: str) -> dict[str, Any]:
        """汇总以 sample_id 为根的整个分样家族的守恒账。"""

        root = self._require_sample(sample_id)
        incident = root.incident_id
        family = self._family_ids(sample_id)
        # 外部进入量只有：根样的初始交接量，以及对家族内任意样本的补样量。
        # 子样 received 全部来自父样 split_out，属于家族内部转移，不能重复计入。
        external_in = root.received
        consumed = Decimal(0)
        balance = Decimal(0)
        for sid in family:
            s = self.samples[sid]
            external_in += s.replenished
            consumed += s.consumed
            balance += s.balance
        # 家族内：根 received 是外部进入；子样 received 来自父样 split_out，
        # 与全家族 split_out 之和相抵。
        split_total = sum((s.split_out for s in (self.samples[i] for i in family)), Decimal(0))
        child_received = sum(
            (s.received for s in (self.samples[i] for i in family) if s.parents),
            Decimal(0),
        )
        conserved = external_in == consumed + balance and split_total == child_received
        return {
            "incident_id": incident,
            "root_sample_id": sample_id,
            "family_sample_ids": sorted(family),
            "external_input": str(external_in),
            "consumed": str(consumed),
            "balance": str(balance),
            "split_out_internal": str(split_total),
            "child_received_internal": str(child_received),
            "conserved": conserved,
        }

    def assert_all_conserved(self) -> None:
        roots = [sid for sid, s in self.samples.items() if not s.parents]
        seen: set[str] = set()
        for root_id in roots:
            report = self.family_report(root_id)
            if not report["conserved"]:
                raise ChainViolation([Problem(
                    "conservation_violation",
                    f"样本家族 {root_id} 数量不守恒: {report}",
                )])
            seen.update(report["family_sample_ids"])
        orphans = set(self.samples) - seen
        if orphans:
            raise ChainViolation([Problem(
                "conservation_violation", f"存在无法归属根样的样本: {sorted(orphans)}",
            )])

    def _family_ids(self, root_id: str) -> set[str]:
        seen = {root_id}
        stack = [root_id]
        while stack:
            cur = self.samples[stack.pop()]
            for child in cur.children:
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        return seen

    # ------------------------------------------------------------------ 辅助

    def _require_sample(self, sample_id: str) -> SampleState:
        sample = self.samples.get(sample_id)
        if sample is None:
            raise ChainViolation([Problem(
                "unknown_sample", f"样本 {sample_id!r} 尚未交接登记", pointer="/sample_id",
            )])
        return sample

    def _entry(self, ev: dict[str, Any], sample: SampleState, detail: dict[str, Any]) -> ChainEntry:
        return ChainEntry(
            seq=len(self.entries) + 1,
            event_id=ev["event_id"],
            action=ev["action"],
            occurred_at=ev["occurred_at"],
            sample_id=sample.sample_id,
            detail=detail,
            balance_after=str(sample.balance),
            custodian_after=sample.custodian,
        )

    def _validate_basic(self, ev: Any) -> list[Problem]:
        problems: list[Problem] = []
        if not isinstance(ev, dict):
            return [Problem("type_mismatch", "事件必须是对象", pointer="/")]
        action = ev.get("action")
        if action not in ("handoff", "split", "consume", "replenish"):
            problems.append(Problem("invalid_value",
                                    f"action 必须是 handoff/split/consume/replenish，得到 {action!r}",
                                    pointer="/action"))
        for key in ("event_id", "occurred_at"):
            value = ev.get(key)
            if not isinstance(value, str) or not value.strip():
                problems.append(Problem("missing_field", f"事件缺少非空字符串字段 {key!r}",
                                        pointer=f"/{key}"))
            elif key == "occurred_at":
                # 非法时间不得形成领域记录
                try:
                    parse_instant(value)
                except ValueError:
                    problems.append(Problem("invalid_time",
                                            f"occurred_at 非法: {value!r}",
                                            pointer="/occurred_at"))
        if action == "handoff":
            # incident_id/matrix/unit 仅首次交接必填，在处理器内按既有样本区分；
            # 既有样本的纯保管转移 quantity 允许为 0（不改变任何数量）。
            self._validate_quantified(ev, ("sample_id", "from_party", "to_party"), problems,
                                      allow_zero=True)
        elif action == "split":
            self._validate_quantified(ev, ("sample_id", "child_sample_id", "from_party", "to_party"),
                                      problems)
            if "assay" in ev and ev["assay"] not in _ASSAYS:
                problems.append(Problem("invalid_value",
                                        f"assay 必须是 {list(_ASSAYS)} 之一", pointer="/assay"))
        elif action == "consume":
            self._validate_quantified(ev, ("sample_id", "by_party"), problems)
            if "assay" in ev and ev["assay"] not in _ASSAYS:
                problems.append(Problem("invalid_value",
                                        f"assay 必须是 {list(_ASSAYS)} 之一", pointer="/assay"))
        elif action == "replenish":
            self._validate_quantified(ev, ("sample_id", "from_party"), problems)
        return problems

    @staticmethod
    def _validate_quantified(ev: dict, str_keys: tuple[str, ...], problems: list[Problem],
                             allow_zero: bool = False) -> None:
        for key in str_keys:
            if not isinstance(ev.get(key), str) or not ev[key].strip():
                problems.append(Problem("missing_field",
                                        f"缺少非空字符串字段 {key!r}", pointer=f"/{key}"))
        if "quantity" in ev:
            _q(ev["quantity"], "/quantity", problems, allow_zero=allow_zero)
        else:
            problems.append(Problem("missing_field", "缺少数量字段 'quantity'", pointer="/quantity"))

    # WAL/快照 ---------------------------------------------------------------

    def events_for_replay(self) -> list[dict[str, Any]]:
        return [self._events[e.event_id] for e in self.entries]

    @classmethod
    def replay(cls, events: list[dict[str, Any]]) -> "ChainLedger":
        ledger = cls()
        ledger.apply_many(events)
        return ledger
