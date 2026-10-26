#!/usr/bin/env python3

from pathlib import Path
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: tamper.py INPUT OUTPUT")

data = Path(sys.argv[1]).read_bytes()
if not data.endswith(b"\n"):
    raise SystemExit("input manifest has no canonical trailing newline")

# Preserve valid JSON and every parsed semantic field while changing the
# sealed byte identity.
Path(sys.argv[2]).write_bytes(data[:-1] + b" \n")
