"""只接受“唯一、完整”的一个 JSON 值的解析器。

与标准库 ``json.loads`` 的关键差异：

* 对象中出现重复键时不静默采用后者，而是收集为 ``duplicate_key`` 问题；
* 根值之后若存在尾随内容，抛出 ``trailing_content``；
* 拒绝 NaN / Infinity / 裸控制字符 / 孤立代理项；
* 每个值与键都记录 1 基行号、0 基列号，供问题定位。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import Problem, StrictJsonError


@dataclass(frozen=True)
class Node:
    """带源码位置的 JSON 节点。

    容器节点的 value 仍是普通 dict/list，但其中的子元素全部是 Node，
    需用 :meth:`unwrap` 还原成纯 Python 值。
    """

    value: Any
    line: int
    column: int
    kind: str

    def unwrap(self) -> Any:
        if self.kind == "object":
            return {k: v.unwrap() for k, v in self.value.items()}
        if self.kind == "array":
            return [v.unwrap() for v in self.value]
        return self.value


_WHITESPACE = " \t\n\r"
_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.n = len(text)
        self.p = 0
        self.problems: list[Problem] = []
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        self.line_starts = starts

    def lc(self, pos: int) -> tuple[int, int]:
        # 二分找到 pos 所在行
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, pos - self.line_starts[lo]

    def here(self) -> tuple[int, int]:
        return self.lc(self.p)

    def fail(self, message: str, code: str = "syntax", pos: int | None = None) -> None:
        line, col = self.lc(self.p if pos is None else pos)
        raise StrictJsonError([Problem(code, message, line, col)])

    def skip_ws(self) -> None:
        while self.p < self.n and self.text[self.p] in _WHITESPACE:
            self.p += 1

    def parse_root(self) -> Node:
        self.skip_ws()
        node = self.parse_value()
        self.skip_ws()
        if self.p != self.n:
            line, col = self.here()
            self.problems.append(
                Problem(
                    "trailing_content",
                    f"JSON 根值结束后存在未解析内容: {self.text[self.p]!r}",
                    line,
                    col,
                )
            )
        if self.problems:
            raise StrictJsonError(self.problems)
        return node

    def parse_value(self) -> Node:
        self.skip_ws()
        if self.p >= self.n:
            self.fail("文档在预期值处结束")
        start = self.p
        ch = self.text[self.p]
        if ch == "{":
            return self.parse_object()
        if ch == "[":
            return self.parse_array()
        if ch == '"':
            return self.parse_string()
        if ch == "-" or ch.isdigit():
            return self.parse_number()
        for literal, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(literal, self.p):
                self.p += len(literal)
                line, col = self.lc(start)
                return Node(value, line, col, "boolean" if isinstance(value, bool) else "null")
        self.fail(f"非法的 JSON 值起始字符: {ch!r}")

    def parse_object(self) -> Node:
        start = self.p
        line, col = self.lc(start)
        self.p += 1  # {
        items: dict[str, Node] = {}
        key_positions: dict[str, tuple[int, int]] = {}
        self.skip_ws()
        if self._peek() == "}":
            self.p += 1
            return Node(items, line, col, "object")
        while True:
            self.skip_ws()
            if self._peek() != '"':
                self.fail("对象键必须是双引号字符串")
            key_node = self.parse_string()
            key = key_node.value
            self.skip_ws()
            if self._peek() != ":":
                self.fail("对象键与值之间缺少 ':'")
            self.p += 1
            value = self.parse_value()
            if key in items:
                first_line, first_col = key_positions[key]
                self.problems.append(
                    Problem(
                        "duplicate_key",
                        (
                            f"重复键 {key!r}：首次出现于 line {first_line} column {first_col}，"
                            "重复键会导致取值不确定，整条文件被拒绝"
                        ),
                        key_node.line,
                        key_node.column,
                    )
                )
            else:
                items[key] = value
                key_positions[key] = (key_node.line, key_node.column)
            self.skip_ws()
            ch = self._peek()
            if ch == ",":
                self.p += 1
                continue
            if ch == "}":
                self.p += 1
                return Node(items, line, col, "object")
            self.fail("对象成员之间需要 ','，对象结束需要 '}'")

    def parse_array(self) -> Node:
        start = self.p
        line, col = self.lc(start)
        self.p += 1  # [
        items: list[Node] = []
        self.skip_ws()
        if self._peek() == "]":
            self.p += 1
            return Node(items, line, col, "array")
        while True:
            items.append(self.parse_value())
            self.skip_ws()
            ch = self._peek()
            if ch == ",":
                self.p += 1
                continue
            if ch == "]":
                self.p += 1
                return Node(items, line, col, "array")
            self.fail("数组元素之间需要 ','，数组结束需要 ']'")

    def parse_string(self) -> Node:
        start = self.p
        line, col = self.lc(start)
        self.p += 1  # opening quote
        out: list[str] = []
        while True:
            if self.p >= self.n:
                self.fail("字符串未闭合", pos=start)
            ch = self.text[self.p]
            if ch == '"':
                self.p += 1
                return Node("".join(out), line, col, "string")
            if ch == "\\":
                self.p += 1
                if self.p >= self.n:
                    self.fail("转义序列未结束")
                esc = self.text[self.p]
                if esc in _ESCAPES:
                    out.append(_ESCAPES[esc])
                    self.p += 1
                elif esc == "u":
                    out.append(self.parse_uescape())
                else:
                    self.fail(f"非法转义序列: \\{esc}")
                continue
            if ord(ch) < 0x20:
                self.fail("字符串中不允许出现未转义的控制字符")
            out.append(ch)
            self.p += 1

    def parse_uescape(self) -> str:
        # 调用时 self.text[self.p] == 'u'
        pos = self.p
        self.p += 1
        hexpart = self.text[self.p : self.p + 4]
        if len(hexpart) != 4 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
            self.fail("\\u 转义后需要 4 位十六进制数", pos=pos)
        code = int(hexpart, 16)
        self.p += 4
        if 0xD800 <= code <= 0xDBFF:
            if self.text[self.p : self.p + 2] != "\\u":
                self.fail("高代理项后缺少配对的低代理项 \\uXXXX", pos=pos)
            self.p += 2
            low_hex = self.text[self.p : self.p + 4]
            if len(low_hex) != 4 or any(c not in "0123456789abcdefABCDEF" for c in low_hex):
                self.fail("高代理项后的低代理项格式非法", pos=pos)
            low = int(low_hex, 16)
            self.p += 4
            if not 0xDC00 <= low <= 0xDFFF:
                self.fail("高代理项后必须跟随低代理项", pos=pos)
            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
        elif 0xDC00 <= code <= 0xDFFF:
            self.fail("出现孤立的低代理项", pos=pos)
        return chr(code)

    def parse_number(self) -> Node:
        start = self.p
        line, col = self.lc(start)
        if self._peek() == "-":
            self.p += 1
        if self._peek() == "0":
            self.p += 1
            if self.p < self.n and self.text[self.p].isdigit():
                self.fail("数字不允许前导零")
        elif self._peek() and self._peek().isdigit():
            while self._peek() and self._peek().isdigit():
                self.p += 1
        else:
            self.fail("负号后缺少数字")
        is_float = False
        if self._peek() == ".":
            is_float = True
            self.p += 1
            frac = 0
            while self._peek() and self._peek().isdigit():
                self.p += 1
                frac += 1
            if frac == 0:
                self.fail("小数点后至少需要一位数字")
        if self._peek() in ("e", "E"):
            is_float = True
            self.p += 1
            if self._peek() in ("+", "-"):
                self.p += 1
            exp_digits = 0
            while self._peek() and self._peek().isdigit():
                self.p += 1
                exp_digits += 1
            if exp_digits == 0:
                self.fail("指数部分至少需要一位数字")
        token = self.text[start : self.p]
        value: Any = float(token) if is_float else int(token)
        return Node(value, line, col, "number")

    def _peek(self) -> str:
        return self.text[self.p] if self.p < self.n else ""


def parse_bytes(raw: bytes) -> Node:
    """严格解析原始字节，返回带位置的节点树。"""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJsonError(
            [
                Problem(
                    "encoding",
                    f"原始字节不是合法 UTF-8: {exc.reason}（byte {exc.start}）",
                    None,
                    None,
                )
            ]
        ) from exc
    return _Parser(text).parse_root()
