"""只追加的 WAL（write-ahead log）。

每条记录在内存状态改变**之前**落盘并 fsync；进程崩溃后按顺序重放即可重建。
记录文件为 JSON Lines，每条独占一行，读回时同样走严格解析，损坏行会被
明确定位而不是静默截断。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import Problem, StrictJsonError
from .strictjson import parse_bytes


@dataclass
class WalEntry:
    seq: int
    kind: str
    payload: dict[str, Any]


class WriteAheadLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("ab+")
        self._fh.seek(0)
        self.seq = 0
        for line in self._fh.readlines():
            if line.strip():
                self.seq += 1

    def append(self, kind: str, payload: dict[str, Any]) -> WalEntry:
        self.seq += 1
        record = {"seq": self.seq, "kind": kind, "payload": payload}
        line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        self._fh.write(line)
        self._fh.flush()
        os.fsync(self._fh.fileno())
        return WalEntry(self.seq, kind, payload)

    def replay(self) -> list[WalEntry]:
        entries: list[WalEntry] = []
        raw = self.path.read_bytes()
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                node = parse_bytes(line)
            except StrictJsonError as exc:
                raise StrictJsonError([
                    Problem(p.code, f"WAL 第 {lineno} 行损坏: {p.message}",
                            lineno, p.column, p.pointer)
                    for p in exc.problems
                ]) from exc
            value = node.unwrap()
            if not isinstance(value, dict) or set(value) != {"seq", "kind", "payload"}:
                raise StrictJsonError([Problem(
                    "wal_shape", f"WAL 第 {lineno} 行记录形状非法", lineno, None,
                )])
            entries.append(WalEntry(int(value["seq"]), value["kind"], value["payload"]))
        expected = list(range(1, len(entries) + 1))
        actual = [e.seq for e in entries]
        if actual != expected:
            raise StrictJsonError([Problem(
                "wal_seq_gap", f"WAL 序号不连续: 期望 {expected}，实际 {actual}",
            )])
        return entries

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "WriteAheadLog":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
