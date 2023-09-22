#!/usr/bin/env python3
import json
import subprocess

try:
    out = subprocess.check_output(["cargo", "read-manifest"])
    print(json.loads(out)["version"])
except FileNotFoundError:
    print("unknown")
