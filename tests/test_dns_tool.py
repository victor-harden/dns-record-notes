import json
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "tools"))
import dns_tool

SAMPLE = BASE / "tests" / "sample_dig.txt"


class ParseTests(unittest.TestCase):
    def test_parses_records(self):
        records = dns_tool.parse_dig(SAMPLE.read_text())
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0]["type"], "A")

    def test_ignores_comments(self):
        records = dns_tool.parse_dig(SAMPLE.read_text())
        self.assertTrue(all(r["name"] == "example.com." for r in records))

    def test_mx_data(self):
        records = dns_tool.parse_dig(SAMPLE.read_text())
        mx = next(r for r in records if r["type"] == "MX")
        self.assertEqual(mx["data"], "10 mail.example.com.")

    def test_ttl(self):
        records = dns_tool.parse_dig(SAMPLE.read_text())
        self.assertEqual(records[0]["ttl"], 300)


class ValidationTests(unittest.TestCase):
    def test_valid_a(self):
        result = dns_tool.validate_record("example.com. 300 IN A 192.0.2.1")
        self.assertTrue(result["valid"])

    def test_invalid_a(self):
        with self.assertRaises(ValueError):
            dns_tool.validate_record("example.com. 300 IN A 999.1.1.1")

    def test_aaaa_version(self):
        with self.assertRaises(ValueError):
            dns_tool.validate_record("example.com. 300 IN AAAA 192.0.2.1")

    def test_mx_requires_priority(self):
        with self.assertRaises(ValueError):
            dns_tool.validate_record("example.com. 300 IN MX mail.example.com.")

    def test_cname_must_be_qualified(self):
        with self.assertRaises(ValueError):
            dns_tool.validate_record("www.example.com. 300 IN CNAME example.com")

    def test_txt_must_be_quoted(self):
        with self.assertRaises(ValueError):
            dns_tool.validate_record("example.com. 300 IN TXT v=spf1 -all")

    def test_malformed_line(self):
        with self.assertRaises(ValueError):
            dns_tool.validate_record("nonsense")

    def test_cli_parse_json(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = dns_tool.main(["parse", str(SAMPLE), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(buf.getvalue())), 4)


if __name__ == "__main__":
    unittest.main()
