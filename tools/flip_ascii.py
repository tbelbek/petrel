#!/usr/bin/env python3
"""flip_ascii - render the Flipper screen as ASCII art (text) from the USB RPC frame.

Usage:
  flip_ascii.py            one grab -> print ASCII (1:1 pixels, '#'=set)
  flip_ascii.py --block    merge 2x2 pixels per char (smaller, blockier)
  flip_ascii.py --once N   grab N times with a settle and print the last

This exists because the model can't read PNGs; ASCII lets us read menu text and
detect frozen/blank/error screens.
"""
import sys
import time

import flipctl as F

W, H = F.W, F.H


def render(d, block=False):
    if not block:
        lines = []
        for y in range(H):
            row = []
            for x in range(W):
                bit = (d[(y // 8) * W + x] >> (y % 8)) & 1
                row.append("#" if bit else ".")
            lines.append("".join(row))
        return "\n".join(lines)

    # 2x2 -> one char using half-block-ish ASCII (shade by lit count)
    shade = [" ", "\u00b7", "\u2591", "\u2588"]  # 0,1,2,3,4? -> use 5 levels
    shade = [" ", ".", "o", "O", "#"]
    lines = []
    for by in range(0, H, 2):
        row = []
        for bx in range(0, W, 2):
            n = 0
            for dy in range(2):
                for dx in range(2):
                    x, y = bx + dx, by + dy
                    n += (d[(y // 8) * W + x] >> (y % 8)) & 1
            row.append(shade[min(n, 4)])
        lines.append("".join(row))
    return "\n".join(lines)


def grab_one(settle=0.4):
    d = F.grab(s, 1.5)
    return d


def zoom(d, scale=2):
    """Render each pixel as scale x scale characters -> huge block letters."""
    lines = []
    for y in range(H):
        row = []
        for x in range(W):
            bit = (d[(y // 8) * W + x] >> (y % 8)) & 1
            row.append(("#" * scale) if bit else (" " * scale))
        for _ in range(scale):
            lines.append("".join(row))
    return "\n".join(lines)


if __name__ == "__main__":
    block = "--block" in sys.argv
    z = 0
    if "--zoom" in sys.argv:
        z = int(sys.argv[sys.argv.index("--zoom") + 1])
    y0, y1 = 0, H
    if "--crop" in sys.argv:
        i = sys.argv.index("--crop")
        y0, y1 = int(sys.argv[i + 1]), int(sys.argv[i + 2])
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
        if z:
            print(zoom(d, z)[(y0 * z):((y1 * z) if y1 else None)])
        else:
            print(render(d, block))
    finally:
        F.close_session(s)
        s.close()
