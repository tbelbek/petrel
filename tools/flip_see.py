#!/usr/bin/env python3
"""flip_see - drive the Flipper and always come back with a FRESH screen frame.

Why this exists (runbook section "Tuş enjeksiyonunun püf noktası"):

The Flipper only streams a screen frame when the screen CHANGES, and `flipctl ... --shot` returns
the last frame its capture window happened to see. So a shot taken after a key that did not change
anything hands back the PREVIOUS screen - which makes a dropped key indistinguishable from a stale
frame, and makes long key sequences look unreliable when they are not. That ambiguity is exactly
what sent a whole evening of debugging down the wrong path.

This wrapper removes it: send the keys, then force a harmless redraw (UP DOWN - one row up and back
down, net zero, same row) so a fresh frame is guaranteed, then capture that.

Usage:
    flip_see.py shot <out.png> [--settle S]
    flip_see.py press <KEY> [<KEY> ...] [--shot out.png] [--settle S]
    flip_see.py drive <K> [<K> ...] [--shot out.png] [--settle S]

Examples:
    flip_see.py shot /tmp/now.png
    flip_see.py drive DOWN DOWN OK --shot /tmp/step.png --settle 0.4
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FLIPCTL = os.path.join(HERE, "flipctl.py")
PY = sys.executable
REDRAW_SETTLE = "0.35"


def run(args):
    return subprocess.run(
        [PY, FLIPCTL] + args, capture_output=True, text=True, timeout=90
    ).stdout.strip()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd, rest = sys.argv[1], sys.argv[2:]
    out, settle = None, "0.4"
    if "--shot" in rest:
        out = rest[rest.index("--shot") + 1]
        del rest[rest.index("--shot") : rest.index("--shot") + 2]
    if "--settle" in rest:
        settle = rest[rest.index("--settle") + 1]
        del rest[rest.index("--settle") : rest.index("--settle") + 2]

    if cmd == "shot":
        out = rest[0] if rest else "/tmp/see.png"

    if cmd in ("drive", "press", "key"):
        if rest:
            run([cmd] + rest + ["--settle", settle])
        # Harmless redraw so the next frame is definitely current, then capture.
        print(run(["drive", "UP", "DOWN", "--settle", REDRAW_SETTLE, "--shot", out]))
    else:
        print(run([cmd] + rest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
