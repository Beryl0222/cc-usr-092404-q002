"""证据入口测试：重复键、尾随内容、未知字段、非法时间、混合文件。"""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from fungus_chain import (  # noqa: E402
    EvidenceError,
    IntakeRegistry,
    SchemaRejected,
    StrictJsonError,
    load_record,
    parse_bytes,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sample_transfer.json"
SOURCE_FIELD = '"source": "业务样例"'.encode("utf-8")


def with_extra_fields(raw: bytes, extra_json: str) -> bytes:
    """在最小合同对象中、source 之后追加字段（extra_json 形如 ', "lab": "CDC-7"'）。"""

    return raw.replace(SOURCE_FIELD, SOURCE_FIELD + extra_json.encode("utf-8"), 1)


def _problem(exc, code):
    hits = [p for p in exc.problems if p.code == code]
    assert hits, f"未找到问题码 {code}；实际为 {[p.code for p in exc.problems]}"
    return hits[0]


class StrictJsonTest(unittest.TestCase):
    def test_duplicate_record_id_is_rejected_with_position(self):
        raw = (
            b'{\n'
            b'  "schema_version": 1,\n'
            b'  "record_id": "sample-016",\n'
            b'  "domain": "fungus_chain",\n'
            b'  "occurred_at": "2026-09-20T09:00:00+08:00",\n'
            b'  "revision": 1,\n'
            b'  "source": "x",\n'
            b'  "record_id": "sample-999"\n'
            b'}'
        )
        with self.assertRaises(StrictJsonError) as ctx:
            parse_bytes(raw)
        p = _problem(ctx.exception, "duplicate_key")
        self.assertEqual(p.line, 8)
        self.assertIn("record_id", p.message)
        self.assertIn("line 3", p.message)  # 同时报告首次出现位置

    def test_standard_loader_silently_kept_last_but_ours_does_not(self):
        import json

        raw = b'{"record_id": "a", "record_id": "b"}'
        # 对照：标准库确实静默采用后者（事故根因）
        self.assertEqual(json.loads(raw)["record_id"], "b")
        with self.assertRaises(StrictJsonError):
            parse_bytes(raw)

    def test_trailing_content_is_rejected_at_position(self):
        raw = FIXTURE.read_bytes().rstrip() + b" <<<EOF"
        with self.assertRaises(StrictJsonError) as ctx:
            parse_bytes(raw)
        p = _problem(ctx.exception, "trailing_content")
        self.assertIsNotNone(p.line)
        self.assertIsNotNone(p.column)

    def test_two_concatenated_documents_is_trailing_content(self):
        with self.assertRaises(StrictJsonError) as ctx:
            parse_bytes(b'{"a": 1}{"a": 2}')
        _problem(ctx.exception, "trailing_content")

    def test_rejects_non_utf8_and_literals(self):
        with self.assertRaises(StrictJsonError) as ctx:
            parse_bytes(b'{"a": \xff}')
        _problem(ctx.exception, "encoding")
        with self.assertRaises(StrictJsonError):
            parse_bytes(b'{"a": NaN}')
        with self.assertRaises(StrictJsonError):
            parse_bytes(b'{"a": 1} garbage')

    def test_valid_document_unwraps(self):
        node = parse_bytes(FIXTURE.read_bytes())
        self.assertEqual(node.unwrap()["record_id"], "sample-016")


class SchemaGateTest(unittest.TestCase):
    def test_unknown_field_rejected_with_pointer_and_position(self):
        raw = with_extra_fields(FIXTURE.read_bytes(), ', "lab": "CDC-7"')
        with self.assertRaises(SchemaRejected) as ctx:
            load_record_from(raw)
        p = _problem(ctx.exception, "unknown_field")
        self.assertEqual(p.pointer, "/lab")
        self.assertIsNotNone(p.line)

    def test_invalid_time_rejected(self):
        for bad in (
            b'"2026-09-20 09:00:00"',       # 缺时区
            b'"2026-09-20T09:00:00"',       # 裸本地时间
            b'"2026-13-40T25:00:00+08:00"',  # 越界日期
            b'"not-a-time"',
        ):
            raw = FIXTURE.read_bytes().replace(b'"2026-09-20T09:00:00+08:00"', bad)
            with self.assertRaises(SchemaRejected) as ctx:
                load_record_from(raw)
            _problem(ctx.exception, "invalid_time")

    def test_missing_field_and_type_mismatch_are_collected_together(self):
        raw = b'{"schema_version": "1", "domain": "fungus_chain"}'
        with self.assertRaises(SchemaRejected) as ctx:
            parse_and_validate(raw)
        codes = {p.code for p in ctx.exception.problems}
        self.assertIn("type_mismatch", codes)
        self.assertIn("missing_field", codes)

    def test_domain_and_reversion_bounds(self):
        raw = FIXTURE.read_bytes().replace(b'"fungus_chain"', b'"other_domain"')
        with self.assertRaises(SchemaRejected):
            load_record_from(raw)
        raw = FIXTURE.read_bytes().replace(b'"revision": 1', b'"revision": 0')
        with self.assertRaises(SchemaRejected):
            load_record_from(raw)


def load_record_from(raw: bytes):
    """绕过文件系统直接走与 load_record 相同的两阶段入口。"""

    from fungus_chain.intake import validate_envelope

    return validate_envelope(parse_bytes(raw))


def parse_and_validate(raw: bytes):
    from fungus_chain.intake import validate_envelope

    return validate_envelope(parse_bytes(raw))


class QuarantineAndRegistryTest(unittest.TestCase):
    def setUp(self):
        self.good = FIXTURE.read_bytes()
        self.registry = IntakeRegistry()

    def test_quarantine_keeps_raw_bytes_digest_and_locations(self):
        bad = self.good.replace(b'"record_id": "sample-016"',
                                b'"record_id": "x", "record_id": "y"', 1)
        result = self.registry.ingest_bytes(bad, "handoff-016.json")
        self.assertEqual(result.status, "quarantined")
        entry = result.entry
        self.assertEqual(entry.raw, bad)
        self.assertEqual(entry.byte_sha256, hashlib.sha256(bad).hexdigest())
        self.assertEqual(entry.byte_length, len(bad))
        self.assertEqual(entry.stage, "json")
        self.assertTrue(any(p.code == "duplicate_key" and p.line is not None
                            for p in entry.problems))

    def test_schema_quarantine_retains_positions(self):
        bad = with_extra_fields(self.good, ', "extra": 1')
        result = self.registry.ingest_bytes(bad, "handoff-017.json")
        self.assertEqual(result.status, "quarantined")
        self.assertEqual(result.entry.stage, "schema")
        self.assertEqual(result.entry.code, "unknown_field")

    def test_same_bytes_resend_is_not_registered_twice(self):
        first = self.registry.ingest_bytes(self.good, "handoff.json")
        second = self.registry.ingest_bytes(self.good, "handoff.json")
        self.assertEqual(first.status, "accepted")
        self.assertEqual(second.status, "duplicate")
        self.assertIs(second.record, first.record)
        self.assertEqual(self.registry.quarantine, [])

    def test_bad_bytes_resend_does_not_duplicate_quarantine(self):
        bad = self.good + b" trailing"
        r1 = self.registry.ingest_bytes(bad, "handoff.json")
        r2 = self.registry.ingest_bytes(bad, "handoff.json")
        self.assertEqual(r1.status, "quarantined")
        self.assertEqual(r2.status, "quarantined")
        self.assertEqual(len(self.registry.quarantine), 1)

    def test_same_filename_different_content_holds_association(self):
        other = self.good.replace(b"sample-016", b"sample-017")
        r1 = self.registry.ingest_bytes(self.good, "handoff.json")
        r2 = self.registry.ingest_bytes(other, "handoff.json")
        self.assertEqual(r1.status, "accepted")
        self.assertEqual(r2.status, "quarantined")
        self.assertEqual(r2.entry.code, "name_content_conflict")
        # 暂停期间再次送达（无论哪份内容）都不能登记
        r3 = self.registry.ingest_bytes(other, "handoff.json")
        self.assertEqual(r3.status, "quarantined")
        self.assertEqual(r3.entry.code, "name_content_conflict")
        held_again = self.registry.ingest_bytes(self.good, "handoff.json")
        self.assertEqual(held_again.status, "duplicate")  # 已接受的那份仍幂等
        self.registry.release_hold("handoff.json")

    def test_mixed_batch_final_state(self):
        """一个混合批次：1 份合法、4 份非法，各自归位且可定位。"""

        cases = [
            ("ok.json", self.good, "accepted"),
            ("dup.json", self.good.replace(b'"record_id": "sample-016"',
                                           b'"record_id": "a", "record_id": "b"', 1),
             "quarantined"),
            ("trail.json", self.good.rstrip() + b" <>", "quarantined"),
            ("unknown.json", with_extra_fields(self.good, ', "x": 1'), "quarantined"),
            ("badt.json", self.good.replace(b'"2026-09-20T09:00:00+08:00"',
                                            b'"2026/09/20 09:00"'), "quarantined"),
        ]
        outcomes = [(name, self.registry.ingest_bytes(raw, name).status)
                    for name, raw, _ in cases]
        self.assertEqual(outcomes, [(n, s) for n, _, s in cases])
        accepted = [r for r in outcomes if r[1] == "accepted"]
        self.assertEqual(len(accepted), 1)
        stages = sorted(e.stage for e in self.registry.quarantine)
        self.assertEqual(stages, ["json", "json", "schema", "schema"])
        # 每份隔离都留有原始字节摘要
        for entry, (_, raw, _) in zip(self.registry.quarantine, cases[1:]):
            self.assertEqual(entry.byte_sha256, hashlib.sha256(raw).hexdigest())

    def test_existing_contract_entrypoint_still_loads_fixture(self):
        item = load_record(FIXTURE)
        self.assertEqual(item.domain, "fungus_chain")
        self.assertGreater(item.revision, 0)


if __name__ == "__main__":
    unittest.main()
