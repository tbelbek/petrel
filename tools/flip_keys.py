#!/usr/bin/env python3
"""flip_keys - send a key sequence over the Flipper CLI in ONE port session.

No RPC (an RPC session costs ~20 KB of the FAP's ~28 KB free heap and has
crashed the device). Each key is PRESS+SHORT+RELEASE, which is what the app
needs; a lone SHORT is swallowed.

Usage: flip_keys.py down down ok --settle 0.1
"""
import sys
import time

import serial

PORT = "/dev/cu.usbmodemflip_Uy0th11"


def main():
    args = sys.argv[1:]
    settle = 0.12
    keys = []
    i = 0
    while i < len(args):
        if args[i] == "--settle" and i + 1 < len(args):
            settle = float(args[i + 1])
            i += 2
            continue
        keys.append(args[i])
        i += 1

    p = serial.Serial(PORT, 115200, timeout=0.3, write_timeout=5)
    try:
        p.reset_input_buffer()
        p.write(b"\r")
        time.sleep(0.3)
        p.read(8192)
        for k in keys:
            for t in ("press", "short", "release"):
                p.write(("input send %s %s\r" % (k.lower(), t)).encode())
                time.sleep(settle)
        time.sleep(0.3)
        p.read(65536)
    finally:
        p.close()
    print("sent %d keys in one session" % len(keys))


if __name__ == "__main__":
    main()
