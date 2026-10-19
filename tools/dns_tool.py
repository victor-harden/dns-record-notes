#!/usr/bin/env python3
"""Parse dig output and validate DNS records."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path

LINE = re.compile(
    r"^(?P<name>\S+)\s+(?P<ttl>\d+)\s+(?P<class>IN|CH)\s+(?P<type>[A-Z0-9]+)\s+(?P<data>.+)$"
)


def parse_dig(text: str):
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        match = LINE.match(line)
        if not match:
            continue
        records.append({
            "name": match.group("name"),
            "ttl": int(match.group("ttl")),
            "type": match.group("type"),
            "data": match.group("data").strip(),
        })
    return records


def validate_record(line: str) -> dict:
    match = LINE.match(line.strip())
    if not match:
        raise ValueError("expected: <name> <ttl> IN <type> <data>")
    rtype = match.group("type")
    data = match.group("data").strip()
    if rtype in ("A", "AAAA"):
        try:
            ip = ipaddress.ip_address(data)
        except ValueError as exc:
            raise ValueError(f"invalid {rtype} address: {data}") from exc
        expected = 4 if rtype == "A" else 6
        if ip.version != expected:
            raise ValueError(f"{rtype} requires IPv{expected}")
    elif rtype == "MX":
        parts = data.split()
        if len(parts) != 2 or not parts[0].isdigit():
            raise ValueError("MX data must be '<priority> <host>'")
    elif rtype == "CNAME":
        if not data.endswith("."):
            raise ValueError("CNAME target should be fully qualified (end with '.')")
    elif rtype == "TXT":
        if not (data.startswith('"') and data.endswith('"')):
            raise ValueError("TXT data should be quoted")
    else:
        raise ValueError(f"unsupported record type for validation: {rtype}")
    return {"name": match.group("name"), "ttl": int(match.group("ttl")),
            "type": rtype, "data": data, "valid": True}


def live_lookup(name: str):
    try:
        infos = socket.getaddrinfo(name, None)
    except OSError as exc:
        raise ValueError(f"lookup failed: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="DNS record helper")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse")
    p.add_argument("file", type=Path)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("validate")
    p.add_argument("record")

    p = sub.add_parser("lookup")
    p.add_argument("name")

    args = parser.parse_args(argv)
    try:
        if args.command == "parse":
            records = parse_dig(args.file.read_text(encoding="utf-8"))
            if args.json:
                print(json.dumps(records, indent=2))
            else:
                for record in records:
                    print(f"{record['name']:<30} {record['ttl']:>6} {record['type']:<6} "
                          f"{record['data']}")
        elif args.command == "validate":
            print(json.dumps(validate_record(args.record), indent=2))
        else:
            for address in live_lookup(args.name):
                print(address)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
