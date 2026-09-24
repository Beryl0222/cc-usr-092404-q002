"""证据入口测试：重复键、尾随内容、未知字段、非法时间、混合文件。

这些问题必须在形成领域记录前被稳定且可定位地拒绝，原始字节摘要与
问题位置随隔离记录保留。
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scenario import fresh_ledger

from fungus_chain import EvidenceIngress, EvidenceRejected, load_record

VALID = (
    '{\n'
    '  "schema_version": 1,\n'
    '  "record_id": "sample-016",\n'
    '  "domain": "fungus_chain",\n'
    '  "occurred_at": "2026-09-20T09:00:00+08:00",\n'
    '  "revision": 1,\n'
    '  "source": "业务样例"\n'
    '}\n'
).encode("utf-8")


class EnvelopeIngressTest(unittest.TestCase):
    def setUp(self):
        self.ingress = EvidenceIngress()

    def reject(self, raw: bytes, name: str = "case.json"):
        result = self.ingress.submit_bytes(raw, name)
        self.assertFalse(result.ok)
        self.assertIsNone(result.record)
        self.assertIsNotNone(result.quarantine)
        with self.assertRaises(EvidenceRejected):
            result.unwrap()
        return result.quarantine

    def test_valid_bytes_form_record(self):
        result = self.ingress.submit_bytes(VALID, "ok.json")
        self.assertTrue(result.ok)
        self.assertEqual(result.unwrap().record_id, "sample-016")
        self.assertEqual(self.ingress.quarantines, [])

    def test_duplicate_record_id_is_rejected_not_last_wins(self):
        # 事故根源：同一对象两次 record_id，标准 json.loads 静默取后值，
        # 急诊保存的采样编号被实验室回执编号顶替。
        raw = (
            '{\n'
            '  "record_id": "ER-SAVED-016",\n'
            '  "schema_version": 1,\n'
            '  "record_id": "LAB-ECHO-999",\n'
            '  "domain": "fungus_chain",\n'
            '  "occurred_at": "2026-09-20T09:00:00+08:00",\n'
            '  "revision": 1,\n'
            '  "source": "急诊交接"\n'
            '}\n'
        ).encode("utf-8")
        # 先固定标准库的危险行为作为对照：它确实会取后值。
        self.assertEqual(json.loads(raw)["record_id"], "LAB-ECHO-999")
        q = self.reject(raw, "handoff.json")
        issue = next(i for i in q.issues if i.code == "duplicate_key")
        self.assertEqual(issue.path, "/record_id")
        # 定位到后一个键：第 4 行第 3 列，并保留字节偏移。
        self.assertEqual((issue.line, issue.column), (4, 3))
        self.assertIsNotNone(issue.byte_offset)
        self.assertIn("首次出现", issue.message)

    def test_duplicate_key_in_nested_business_file(self):
        ledger = fresh_ledger(tempfile.mkdtemp())
        raw = (
            b'{\n'
            b'  "schema_version": 1,\n'
            b'  "message_id": "dup-nested",\n'
            b'  "command": "intake",\n'
            b'  "occurred_at": "2026-09-20T09:00:00+08:00",\n'
            b'  "payload": {\n'
            b'    "incident_id": "inc-1",\n'
            b'    "samples": [\n'
            b'      {"sample_id": "a", "sample_id": "b", "specimen": "x",\n'
            b'       "tests": ["toxin"], "quantity": 1, "unit": "g"}\n'
            b'    ]\n'
            b'  }\n'
            b'}\n'
        )
        outcome = ledger.submit_bytes(raw, "intake-dup.json")
        self.assertEqual(outcome.kind, "quarantined")
        issue = next(
            i for i in outcome.quarantine.issues if i.code == "duplicate_key"
        )
        self.assertEqual(issue.path, "/payload/samples/0/sample_id")
        self.assertEqual(issue.line, 9)
        # 台账中绝无该事件或样本。
        self.assertNotIn("inc-1", ledger.incidents)
        self.assertEqual(ledger.samples, {})

    def test_trailing_content_two_concatenated_objects(self):
        raw = VALID + VALID  # 混合文件：两个对象首尾拼接
        q = self.reject(raw, "mixed.json")
        issue = next(i for i in q.issues if i.code == "trailing_content")
        # 第二个对象紧跟在第一个文档结束换行之后：第 9 行第 1 列。
        self.assertEqual((issue.line, issue.column), (9, 1))
        self.assertIsNotNone(issue.byte_offset)

    def test_unknown_field_is_rejected(self):
        raw = VALID.replace(
            '  "source": "业务样例"\n'.encode(),
            '  "source": "业务样例",\n  "lab_tech": "张某"\n'.encode(),
        )
        q = self.reject(raw, "extra.json")
        issue = next(i for i in q.issues if i.code == "unknown_field")
        self.assertEqual(issue.path, "/lab_tech")
        self.assertEqual(issue.line, 8)

    def test_invalid_time_variants(self):
        cases = {
            "naive": b'"2026-09-20T09:00:00"',           # 无时区
            "garbage": b'"2026-09-20 09:00:00+08:00"',   # 非 ISO
            "not-a-date": '"昨天上午"'.encode(),
        }
        for label, time_literal in cases.items():
            with self.subTest(label):
                ingress = EvidenceIngress()
                raw = VALID.replace(
                    b'"2026-09-20T09:00:00+08:00"', time_literal
                )
                result = ingress.submit_bytes(raw, f"time-{label}.json")
                self.assertFalse(result.ok, label)
                issue = next(
                    i for i in result.quarantine.issues if i.code == "invalid_time"
                )
                self.assertEqual(issue.path, "/occurred_at")

    def test_missing_field_and_empty_value_collected_together(self):
        raw = VALID.replace(b'  "revision": 1,\n', b"").replace(
            b'"sample-016"', b'""'
        )
        q = self.reject(raw, "bad.json")
        codes = {i.code for i in q.issues}
        self.assertIn("missing_field", codes)
        self.assertTrue(
            any(i.code == "invalid_value" and i.path == "/record_id" for i in q.issues)
        )

    def test_raw_byte_digest_and_excerpt_preserved(self):
        raw = (
            b'{\n  "schema_version": 1,\n  "record_id": "s1",\n'
            b'  "domain": "fungus_chain",\n'
            b'  "occurred_at": "2026-09-20T09:00:00+08:00",\n'
            b'  "revision": 1,\n  "source": "x",\n  "z": true}\n'
        )
        q = self.reject(raw, "digest.json")
        self.assertEqual(q.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(q.byte_length, len(raw))
        self.assertTrue(q.raw_excerpt.startswith(b"{"))
        self.assertEqual(q.quarantine_id, f"q-{q.sha256[:12]}")
        # 隔离记录可序列化留存。
        persisted = q.to_dict()
        self.assertEqual(persisted["issues"][0]["code"], persisted["issues"][0]["code"])

    def test_syntax_error_location_points_at_bad_token(self):
        raw = b'{"schema_version": 1,}\n'
        q = self.reject(raw, "syntax.json")
        self.assertEqual(q.primary_issue.code, "syntax")
        # 逗号后直接遇到 }：错误定位在闭合花括号，第 1 行第 22 列。
        self.assertEqual((q.primary_issue.line, q.primary_issue.column), (1, 22))

    def test_non_utf8_rejected_with_byte_location(self):
        raw = b'{"record_id": "\xff\xfe' + "坏".encode() + b'"}\n'
        q = self.reject(raw, "gbk.json")
        self.assertEqual(q.primary_issue.code, "encoding")
        self.assertIsNotNone(q.primary_issue.byte_offset)

    def test_bom_rejected(self):
        raw = b"\xef\xbb\xbf" + VALID
        q = self.reject(raw, "bom.json")
        self.assertEqual(q.primary_issue.code, "encoding")

    def test_load_record_path_raises_with_quarantine(self):
        tmp = Path(tempfile.mkdtemp()) / "dup.json"
        tmp.write_bytes(
            b'{"schema_version": 1, "record_id": "a", "record_id": "b",'
            b' "domain": "d", "occurred_at": "2026-09-20T09:00:00+08:00",'
            b' "revision": 1, "source": "s"}'
        )
        with self.assertRaises(EvidenceRejected) as ctx:
            load_record(tmp)
        self.assertEqual(
            ctx.exception.quarantine.primary_issue.code, "duplicate_key"
        )

    def test_mixed_quarantines_are_independent(self):
        """混合批次：重复键文件与尾随文件分别隔离，问题位置互不串扰。"""
        ledger = fresh_ledger(tempfile.mkdtemp())
        duplicate_key = (
            b'{"schema_version":1,"message_id":"d2","message_id":"d3",'
            b'"command":"consume","occurred_at":"2026-09-20T09:00:00+08:00",'
            b'"payload":{"sample_id":"s","test":"toxin","quantity":1}}'
        )
        trailing = (
            b'{"schema_version":1,"message_id":"t1","command":"consume",'
            b'"occurred_at":"2026-09-20T09:00:00+08:00",'
            b'"payload":{"sample_id":"s","test":"toxin","quantity":1}}'
            b'{"schema_version":1}'
        )
        self.assertEqual(
            ledger.submit_bytes(duplicate_key, "d.json").kind, "quarantined"
        )
        self.assertEqual(
            ledger.submit_bytes(trailing, "t.json").kind, "quarantined"
        )
        self.assertEqual(len(ledger.quarantines), 2)
        self.assertEqual(
            [i.code for i in ledger.quarantines[0].issues], ["duplicate_key"]
        )
        self.assertEqual(
            [i.code for i in ledger.quarantines[1].issues], ["trailing_content"]
        )
        # 任何隔离文件都未进入领域状态。
        self.assertEqual(ledger.events[-2].kind, "quarantined")
        self.assertEqual(ledger.samples, {})


if __name__ == "__main__":
    unittest.main()
