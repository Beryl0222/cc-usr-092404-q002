"""构造联检交接命令文件的规范字节。

所有命令统一经严格入口进入台账；这些构造器输出键序稳定、无尾随空白的
UTF-8 JSON，供发送方落盘与重送使用。重送必须原样重发同一字节，幂等
判定以 SHA-256 为准。
"""

from __future__ import annotations

import json
from typing import Any

from .commands import (
    CMD_CONSUME,
    CMD_CREATE_CONCLUSION,
    CMD_INTAKE,
    CMD_ISSUE_CONCLUSION,
    CMD_RESULT,
    CMD_REVISE_CONCLUSION,
    CMD_SPLIT,
    CMD_SUPPLEMENT,
)


def _encode(command: str, message_id: str, payload: dict[str, Any], occurred_at: str) -> bytes:
    envelope = {
        "schema_version": 1,
        "message_id": message_id,
        "command": command,
        "occurred_at": occurred_at,
        "payload": payload,
    }
    return (
        json.dumps(envelope, ensure_ascii=False, indent=2, separators=(",", ": ")) + "\n"
    ).encode("utf-8")


def intake(
    *,
    message_id: str,
    occurred_at: str,
    incident_id: str,
    samples: list[dict[str, Any]],
) -> bytes:
    return _encode(
        CMD_INTAKE,
        message_id,
        {"incident_id": incident_id, "samples": samples},
        occurred_at,
    )


def split(
    *,
    message_id: str,
    occurred_at: str,
    parent_sample_id: str,
    children: list[dict[str, int | str]],
    remaining_quantity: int,
) -> bytes:
    return _encode(
        CMD_SPLIT,
        message_id,
        {
            "parent_sample_id": parent_sample_id,
            "children": children,
            "remaining_quantity": remaining_quantity,
        },
        occurred_at,
    )


def consume(
    *,
    message_id: str,
    occurred_at: str,
    sample_id: str,
    test: str,
    quantity: int,
) -> bytes:
    return _encode(
        CMD_CONSUME,
        message_id,
        {"sample_id": sample_id, "test": test, "quantity": quantity},
        occurred_at,
    )


def supplement(
    *,
    message_id: str,
    occurred_at: str,
    incident_id: str,
    sample_id: str,
    specimen: str,
    tests: list[str],
    quantity: int,
    unit: str,
    reason: str,
) -> bytes:
    return _encode(
        CMD_SUPPLEMENT,
        message_id,
        {
            "incident_id": incident_id,
            "sample_id": sample_id,
            "specimen": specimen,
            "tests": tests,
            "quantity": quantity,
            "unit": unit,
            "reason": reason,
        },
        occurred_at,
    )


def result(
    *,
    message_id: str,
    occurred_at: str,
    sample_id: str,
    test: str,
    analyte: str,
    result_value: str,
    critical: bool,
) -> bytes:
    return _encode(
        CMD_RESULT,
        message_id,
        {
            "sample_id": sample_id,
            "test": test,
            "analyte": analyte,
            "result": result_value,
            "critical": critical,
        },
        occurred_at,
    )


def create_conclusion(
    *,
    message_id: str,
    occurred_at: str,
    incident_id: str,
    conclusion_id: str,
    content: str,
    depends_on: list[str],
) -> bytes:
    return _encode(
        CMD_CREATE_CONCLUSION,
        message_id,
        {
            "incident_id": incident_id,
            "conclusion_id": conclusion_id,
            "content": content,
            "depends_on": depends_on,
        },
        occurred_at,
    )


def revise_conclusion(
    *,
    message_id: str,
    occurred_at: str,
    incident_id: str,
    conclusion_id: str,
    content: str,
) -> bytes:
    return _encode(
        CMD_REVISE_CONCLUSION,
        message_id,
        {
            "incident_id": incident_id,
            "conclusion_id": conclusion_id,
            "content": content,
        },
        occurred_at,
    )


def issue_conclusion(
    *,
    message_id: str,
    occurred_at: str,
    incident_id: str,
    conclusion_id: str,
) -> bytes:
    return _encode(
        CMD_ISSUE_CONCLUSION,
        message_id,
        {"incident_id": incident_id, "conclusion_id": conclusion_id},
        occurred_at,
    )


__all__ = [
    "consume",
    "create_conclusion",
    "intake",
    "issue_conclusion",
    "result",
    "revise_conclusion",
    "split",
    "supplement",
]
