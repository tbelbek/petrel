#!/usr/bin/env python3
"""fliplog - stream the Flipper's CLI `log` output to a file (to catch pre-crash logs).

Usage: fliplog.py <out.txt>   (Ctrl-C / crash ends it)
"""
import sys
import time

import serial

PORT = "/dev/cu.usbmodemflip_Uy0th11"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fliplog.txt"

s = serial.Serial(PORT, 115200, timeout=0.2)
s.write(b"\r")
time.sleep(0.4)
s.reset_input_buffer()
s.write(b"log\r")
with open(OUT, "wb", buffering=0) as f:
    try:
        while True:
            c = s.read(4096)
            if c:
                f.write(c)
    except Exception:
        pass
s.close()
