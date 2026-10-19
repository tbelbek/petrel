#!/usr/bin/env python3
"""flip_text - dump the Flipper screen as readable glyph cells (for reading menu text).

Each 5x7 glyph in a text band is printed as its own mini block, so text can be read
letter by letter without OCR. Usage:
  flip_text.py [y0] [y1]    default scans and prints all rows in 8px bands
"""
import sys
import time

import flipctl as F

W, H = F.W, F.H


def px(d, x, y):
    return (d[(y // 8) * W + x] >> (y % 8)) & 1


def band(d, y0, y1):
    """Print rows y0..y1, one char per pixel but only '#'/space, 1:1."""
    for y in range(y0, y1):
        print("".join("#" if px(d, x, y) else "." for x in range(W)))


def glyphs(d, y0, pitch=6):
    """Segment rows y0..y0+7 into `pitch`-wide glyphs, print each glyph as a mini block."""
    for x0 in range(0, W, pitch):
        cols = []
        for y in range(y0, y0 + 8):
            row = "".join("#" if px(d, x0 + dx, y) else " " for dx in range(pitch - 1))
            cols.append(row)
        # only print non-empty glyphs
        if any("#" in c for c in cols):
            print(f"-- x={x0} --")
            for c in cols:
                print("|" + c + "|")


if __name__ == "__main__":
    args = [int(a) for a in sys.argv[1:3] if a.isdigit()]
    s = F.connect()
    try:
        F.send(s, b"\xA2\x01\x00")
        time.sleep(0.5)
        d = None
        for _ in range(3):
            d = F.grab(s, 1.5)
            if d:
                break
            time.sleep(0.3)
        if not d:
            print("NO FRAME")
            sys.exit(1)
        if args and len(args) == 2:
            glyphs(d, args[0])
        elif args:
            band(d, args[0], args[0] + 8)
        else:
            band(d, 0, H)
    finally:
        F.close_session(s)
        s.close()
