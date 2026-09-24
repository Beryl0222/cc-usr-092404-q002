"""严格的 ISO 8601 时间解析。

只接受带日期、完整时分秒和显式时区偏移（``Z`` 或 ``±HH:MM``）的时间，
避免裸本地时间在多机构交接时产生歧义。
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_INSTANT_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$"
)


def parse_instant(value: str) -> datetime:
    """把规范字符串解析为时区感知的 :class:`datetime`，失败时抛出 ValueError。"""

    if not isinstance(value, str):
        raise ValueError("时间必须是字符串")
    match = _INSTANT_RE.match(value)
    if not match:
        raise ValueError(
            "时间格式必须为 YYYY-MM-DDTHH:MM:SS[.fraction] 并带 Z 或 ±HH:MM 时区偏移"
        )
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    microsecond = int((fraction or "").ljust(6, "0")) if fraction else 0
    if zone == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        zh, zm = int(zone[1:3]), int(zone[4:6])
        if zm >= 60 or zh > 23:
            raise ValueError("时区偏移越界")
        tzinfo = timezone(sign * timedelta(hours=zh, minutes=zm))
    try:
        return datetime(
            int(year), int(month), int(day),
            int(hour), int(minute), int(second),
            microsecond, tzinfo,
        )
    except ValueError as exc:
        raise ValueError(f"非法日期时间: {exc}") from exc
