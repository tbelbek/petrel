#!/usr/bin/env python3
"""fwlog - append BW16 firmware debug (CH340) output to a timestamped file."""
import serial
import sys
import time

PORT = "/dev/cu.usbserial-20220"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/fwlog.txt"

s = serial.Serial(PORT, 115200, timeout=0.2)
# Never leave DTR/RTS asserted on the CH340: RTS->BOOT would boot the BW16 into
# download mode (and kill the running app). Drop them the instant the port is open.
try:
    s.dtr = False
    s.rts = False
except Exception:
    pass
with open(OUT, "ab", buffering=0) as f:
    while True:
        c = s.read(4096)
        if c:
            ts = time.strftime("%H:%M:%S")
            for line in c.split(b"\n"):
                if line:
                    f.write(f"{ts} {line.decode('utf-8', 'replace')}\n".encode())
