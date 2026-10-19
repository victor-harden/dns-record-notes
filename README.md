# dns-record-notes

Study notes for the DNS record types that matter in security work, plus a small
tool that parses `dig` output into structured records and validates record
syntax before you paste it into a zone file.

## Features

- `docs/records.md`: A, AAAA, CNAME, MX, TXT, NS, SOA, CAA and what to look for.
- `tools/dns_tool.py parse`: parse saved `dig +noall +answer` output.
- `tools/dns_tool.py validate`: check an A/AAAA/MX/TXT/CNAME record line.
- Optional live A lookup through the resolver when you ask for it.
- Tests use saved dig output; no network needed.

## Installation

```bash
git clone https://github.com/victor-harden/dns-record-notes.git
cd dns-record-notes
```

## Usage

```bash
dig +noall +answer example.com A > answer.txt
python3 tools/dns_tool.py parse answer.txt
python3 tools/dns_tool.py validate "example.com. 300 IN A 192.0.2.1"
python3 tools/dns_tool.py lookup example.com
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
