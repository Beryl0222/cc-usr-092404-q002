"""业务交接命令合同。

急诊、疾控、实验室之间流转的联检交接文件统一采用命令信封：

``schema_version / message_id / command / occurred_at / payload``

``payload`` 的形状随 ``command`` 不同。所有嵌套对象与数组同样拒绝未知
字段；语法层（重复键、尾随内容、编码）由 :mod:`fungus_chain.ingress`
统一负责，本模块只负责信封与各命令 payload 的模式校验。
"""

from __future__ import annotations

from typing import Any

from .ingress import (
    FieldSpec,
    Issue,
    SUPPORTED_SCHEMA_VERSIONS,
    enum_check,
    iso_time,
    non_empty_str,
    validate_fields,
)

# 联检项目：形态学、毒素、分子检测。
TEST_MORPHOLOGY = "morphology"
TEST_TOXIN = "toxin"
TEST_MOLECULAR = "molecular"
PANEL_TESTS = (TEST_MORPHOLOGY, TEST_TOXIN, TEST_MOLECULAR)

CMD_INTAKE = "intake"
CMD_SPLIT = "split"
CMD_CONSUME = "consume"
CMD_SUPPLEMENT = "supplement"
CMD_RESULT = "record_result"
CMD_CREATE_CONCLUSION = "create_conclusion"
CMD_REVISE_CONCLUSION = "revise_conclusion"
CMD_ISSUE_CONCLUSION = "issue_conclusion"
COMMANDS = (
    CMD_INTAKE,
    CMD_SPLIT,
    CMD_CONSUME,
    CMD_SUPPLEMENT,
    CMD_RESULT,
    CMD_CREATE_CONCLUSION,
    CMD_REVISE_CONCLUSION,
    CMD_ISSUE_CONCLUSION,
)

_ENVELOPE_FIELDS: dict[str, FieldSpec] = {
    "schema_version": (
        int,
        lambda v: None
        if v in SUPPORTED_SCHEMA_VERSIONS
        else f"schema_version={v} 不受支持，当前接受 {sorted(SUPPORTED_SCHEMA_VERSIONS)}",
    ),
    "message_id": (str, non_empty_str),
    "command": (str, enum_check(COMMANDS)),
    "occurred_at": (str, iso_time),
    "payload": (dict, None),
}
_ENVELOPE_REQUIRED = ("schema_version", "message_id", "command", "occurred_at", "payload")

_SAMPLE_FIELDS: dict[str, FieldSpec] = {
    "sample_id": (str, non_empty_str),
    "specimen": (str, non_empty_str),
    "tests": (list, None),
    "quantity": (int, lambda v: None if v > 0 else "必须为正数"),
    "unit": (str, non_empty_str),
}
_SAMPLE_REQUIRED = ("sample_id", "specimen", "tests", "quantity", "unit")

_CHILD_FIELDS: dict[str, FieldSpec] = {
    "sample_id": (str, non_empty_str),
    "quantity": (int, lambda v: None if v > 0 else "必须为正数"),
    "tests": (list, None),
}
_CHILD_REQUIRED = ("sample_id", "quantity")

_SUPPLEMENT_FIELDS: dict[str, FieldSpec] = {
    "incident_id": (str, non_empty_str),
    "sample_id": (str, non_empty_str),
    "specimen": (str, non_empty_str),
    "tests": (list, None),
    "quantity": (int, lambda v: None if v > 0 else "必须为正数"),
    "unit": (str, non_empty_str),
    "reason": (str, non_empty_str),
}
_SUPPLEMENT_REQUIRED = (
    "incident_id",
    "sample_id",
    "specimen",
    "tests",
    "quantity",
    "unit",
    "reason",
)

_PAYLOAD_FIELDS: dict[str, dict[str, FieldSpec]] = {
    CMD_INTAKE: {
        "incident_id": (str, non_empty_str),
        "samples": (list, None),
    },
    CMD_SPLIT: {
        "parent_sample_id": (str, non_empty_str),
        "children": (list, None),
        "remaining_quantity": (int, lambda v: None if v >= 0 else "不允许为负数"),
    },
    CMD_CONSUME: {
        "sample_id": (str, non_empty_str),
        "test": (str, enum_check(PANEL_TESTS)),
        "quantity": (int, lambda v: None if v > 0 else "必须为正数"),
    },
    CMD_RESULT: {
        "sample_id": (str, non_empty_str),
        "test": (str, enum_check(PANEL_TESTS)),
        "analyte": (str, non_empty_str),
        "result": (str, non_empty_str),
        "critical": (bool, None),
    },
    CMD_SUPPLEMENT: _SUPPLEMENT_FIELDS,
    CMD_CREATE_CONCLUSION: {
        "incident_id": (str, non_empty_str),
        "conclusion_id": (str, non_empty_str),
        "content": (str, non_empty_str),
        "depends_on": (list, None),
    },
    CMD_REVISE_CONCLUSION: {
        "incident_id": (str, non_empty_str),
        "conclusion_id": (str, non_empty_str),
        "content": (str, non_empty_str),
    },
    CMD_ISSUE_CONCLUSION: {
        "incident_id": (str, non_empty_str),
        "conclusion_id": (str, non_empty_str),
    },
}
_PAYLOAD_REQUIRED: dict[str, tuple[str, ...]] = {
    CMD_INTAKE: ("incident_id", "samples"),
    CMD_SPLIT: ("parent_sample_id", "children", "remaining_quantity"),
    CMD_CONSUME: ("sample_id", "test", "quantity"),
    CMD_RESULT: ("sample_id", "test", "analyte", "result", "critical"),
    CMD_CREATE_CONCLUSION: (
        "incident_id",
        "conclusion_id",
        "content",
        "depends_on",
    ),
    CMD_REVISE_CONCLUSION: ("incident_id", "conclusion_id", "content"),
    CMD_ISSUE_CONCLUSION: ("incident_id", "conclusion_id"),
    CMD_SUPPLEMENT: _SUPPLEMENT_REQUIRED,
}


def _span_map(
    key_spans: tuple[tuple[str, int, str], ...]
) -> dict[str, int]:
    return {f"{path}/{key}": offset for path, offset, key in key_spans}


def _issue_at(
    spans: dict[str, int], pointer: str, code: str, message: str
) -> Issue:
    return Issue(code=code, message=message, char_offset=spans.get(pointer), path=pointer)


def _validate_tests(
    value: list[Any], pointer: str, spans: dict[str, int]
) -> list[Issue]:
    issues: list[Issue] = []
    if not value:
        issues.append(
            _issue_at(spans, pointer, "invalid_value", "联检项目列表不能为空")
        )
    seen: set[str] = set()
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            issues.append(
                Issue(
                    code="invalid_type",
                    message=f"联检项目必须是字符串，实际为 {type(item).__name__}",
                    path=f"{pointer}/{idx}",
                )
            )
            continue
        if item not in PANEL_TESTS:
            issues.append(
                Issue(
                    code="invalid_value",
                    message=f"未知联检项目 {item!r}，允许 {list(PANEL_TESTS)}",
                    path=f"{pointer}/{idx}",
                )
            )
        if item in seen:
            issues.append(
                Issue(
                    code="invalid_value",
                    message=f"联检项目 {item!r} 重复",
                    path=f"{pointer}/{idx}",
                )
            )
        seen.add(item)
    return issues


def _validate_samples(
    value: Any, pointer: str, key_spans: tuple[tuple[str, int, str], ...]
) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(value, list):
        return issues  # 类型问题已由上层记录
    spans = _span_map(key_spans)
    if not value:
        issues.append(_issue_at(spans, pointer, "invalid_value", "至少交接一个样本"))
    seen_ids: set[str] = set()
    for idx, sample in enumerate(value):
        sample_pointer = f"{pointer}/{idx}"
        if not isinstance(sample, dict):
            issues.append(
                Issue(
                    code="invalid_type",
                    message=f"样本必须是对象，实际为 {type(sample).__name__}",
                    path=sample_pointer,
                )
            )
            continue
        issues.extend(
            validate_fields(
                sample,
                key_spans,
                _SAMPLE_FIELDS,
                _SAMPLE_REQUIRED,
                pointer=sample_pointer,
            )
        )
        sample_id = sample.get("sample_id")
        if isinstance(sample_id, str) and sample_id in seen_ids:
            issues.append(
                _issue_at(
                    spans,
                    f"{sample_pointer}/sample_id",
                    "invalid_value",
                    f"同一交接单内样本编号 {sample_id!r} 重复",
                )
            )
        if isinstance(sample_id, str):
            seen_ids.add(sample_id)
        if isinstance(sample.get("tests"), list):
            issues.extend(
                _validate_tests(sample["tests"], f"{sample_pointer}/tests", spans)
            )
    return issues


def _validate_children(
    value: Any, pointer: str, key_spans: tuple[tuple[str, int, str], ...]
) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(value, list):
        return issues
    spans = _span_map(key_spans)
    if not value:
        issues.append(_issue_at(spans, pointer, "invalid_value", "拆分至少产生一个子样"))
    seen: set[str] = set()
    for idx, child in enumerate(value):
        child_pointer = f"{pointer}/{idx}"
        if not isinstance(child, dict):
            issues.append(
                Issue(
                    code="invalid_type",
                    message=f"子样必须是对象，实际为 {type(child).__name__}",
                    path=child_pointer,
                )
            )
            continue
        issues.extend(
            validate_fields(
                child,
                key_spans,
                _CHILD_FIELDS,
                _CHILD_REQUIRED,
                pointer=child_pointer,
            )
        )
        if isinstance(child.get("tests"), list):
            issues.extend(
                _validate_tests(child["tests"], f"{child_pointer}/tests", spans)
            )
        child_id = child.get("sample_id")
        if isinstance(child_id, str):
            if child_id in seen:
                issues.append(
                    _issue_at(
                        spans,
                        f"{child_pointer}/sample_id",
                        "invalid_value",
                        f"子样编号 {child_id!r} 重复",
                    )
                )
            seen.add(child_id)
    return issues


def validate_command(
    value: dict[str, Any],
    key_spans: tuple[tuple[str, int, str], ...],
) -> list[Issue]:
    """校验命令信封及其 payload，返回全部可定位问题。"""
    spans = _span_map(key_spans)
    issues = validate_fields(
        value, key_spans, _ENVELOPE_FIELDS, _ENVELOPE_REQUIRED
    )
    payload = value.get("payload")
    command = value.get("command")
    if not isinstance(payload, dict) or not isinstance(command, str):
        return issues
    if command not in _PAYLOAD_FIELDS:
        return issues  # command 取值问题已记录

    pointer = "/payload"
    issues.extend(
        validate_fields(
            payload,
            key_spans,
            _PAYLOAD_FIELDS[command],
            _PAYLOAD_REQUIRED[command],
            pointer=pointer,
        )
    )

    if command == CMD_INTAKE:
        issues.extend(
            _validate_samples(payload.get("samples"), "/payload/samples", key_spans)
        )
    elif command == CMD_SPLIT:
        issues.extend(
            _validate_children(payload.get("children"), "/payload/children", key_spans)
        )
    elif command == CMD_SUPPLEMENT:
        # 字段已由通用 payload 规范校验，这里只需收窄 tests 数组。
        if isinstance(payload.get("tests"), list):
            issues.extend(
                _validate_tests(payload["tests"], "/payload/tests", spans)
            )
    elif command == CMD_CREATE_CONCLUSION:
        depends = payload.get("depends_on")
        if isinstance(depends, list):
            issues.extend(_validate_tests(depends, "/payload/depends_on", spans))

    return issues


__all__ = [
    "CMD_CONSUME",
    "CMD_CREATE_CONCLUSION",
    "CMD_INTAKE",
    "CMD_ISSUE_CONCLUSION",
    "CMD_RESULT",
    "CMD_REVISE_CONCLUSION",
    "CMD_SPLIT",
    "CMD_SUPPLEMENT",
    "COMMANDS",
    "PANEL_TESTS",
    "TEST_MORPHOLOGY",
    "TEST_MOLECULAR",
    "TEST_TOXIN",
    "validate_command",
]
