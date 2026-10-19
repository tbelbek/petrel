#!/usr/bin/env python3
"""Static audit of the firmware's command dispatch.

The chain is a flat `}else if(readString.substring(0,N)=="CMD"){...}` list, so two things bite:
  1. Wrong length: substring(0,N) with N != len("CMD") never matches (bit us with SNIFFDEAUTH).
  2. Prefix shadowing: an earlier short prefix swallows a later longer command
     (bit us with KARMA swallowing KARMALIST - every poll re-enabled the responder).

Run this after adding or renaming a command; it is much cheaper than finding it on hardware.

Usage: python3 fw_cmd_check.py [path-to-.ino]
"""
import re
import sys

COND = re.compile(r'readString\.substring\(0,(\d+)\)=="([A-Z0-9_]+)"')


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "../RTL8720dn-firmware/RTL8720dn-firmware.ino"
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    conds = []
    for lineno, line in enumerate(lines, 1):
        for m in COND.finditer(line):
            conds.append((lineno, int(m.group(1)), m.group(2)))

    problems = 0
    for i, (lineno, n, cmd) in enumerate(conds):
        if len(cmd) != n:
            print(f"  LENGTH  line {lineno}: substring(0,{n}) == \"{cmd}\" (needs {len(cmd)}) - never matches")
            problems += 1
        for (l2, n2, c2) in conds[i + 1:]:
            if c2.startswith(cmd) and c2 != cmd:
                print(f"  SHADOW  line {lineno}: \"{cmd}\" (0,{n}) swallows \"{c2}\" at line {l2}"
                      f" - move the longer command first")
                problems += 1

    print(f"{len(conds)} conditions checked, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
