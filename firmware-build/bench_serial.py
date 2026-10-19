#!/usr/bin/env python3
"""bench_serial.py - drive the Petrel BW16 firmware over USB serial (no FAP).

The firmware reads commands on both Serial1 (Flipper) and Serial (USB/CH340), so the
board can be exercised from the host. Output goes to both UARTs.

Usage:
    python3 bench_serial.py <port> "<cmd>" ["<cmd>@<wait_s>" ...]
  - each command is sent with a trailing newline
  - default wait per command is 0.6s; add @<secs> for slow ones (SCAN, *_SCAN, CAPTURE)
Examples:
    python3 bench_serial.py /dev/cu.usbserial-20220 "PING" "HELLO"
    python3 bench_serial.py /dev/cu.usbserial-20220 "PMFSCAN 6 5@6" "STASCAN 6 8@9"
"""
import sys
import time

import serial


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port = sys.argv[1]
    ser = serial.Serial(port, 115200, timeout=0.4)
    try:
        ser.dtr = False  # don't hold the board in reset/bootloader
        ser.rts = False
        time.sleep(0.3)
        ser.reset_input_buffer()
        for arg in sys.argv[2:]:
            cmd, _, wait = arg.partition("@")
            wait = float(wait) if wait else 0.6
            ser.write((cmd + "\n").encode())
            ser.flush()
            time.sleep(wait)
            out = ser.read(8192).decode(errors="replace").rstrip()
            print(f"> {cmd}")
            if out:
                print(out)
            print("-" * 40)
    finally:
        ser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
