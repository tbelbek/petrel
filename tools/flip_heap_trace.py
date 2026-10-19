#!/usr/bin/env python3
"""Trace the Flipper's free heap across app actions to find what leaks RAM.

Each iteration: run the UI steps over RPC (session closed cleanly), then read `free`
over the CLI, so we can see which action drains the heap.
"""
import re, sys, time
sys.path.insert(0, ".")
import flipctl as F
import serial

PORT = "/dev/cu.usbmodemflip_Uy0th11"


def free_heap():
    s = serial.Serial(PORT, 115200, timeout=0.5, dsrdtr=False, write_timeout=5)
    try:
        time.sleep(0.4)
        s.reset_input_buffer()
        s.write(b"\r"); time.sleep(0.3); s.read(4096)
        s.write(b"free\r")
        time.sleep(0.8)
        out = s.read(8192).decode(errors="replace")
    finally:
        s.close()
    m = re.search(r"Free heap size:\s*(\d+)", out)
    mn = re.search(r"Minimum heap size:\s*(\d+)", out)
    return (int(m.group(1)) if m else -1, int(mn.group(1)) if mn else -1)


def run(steps):
    s = F.connect()
    F.send(s, b"\xA2\x01\x00")
    time.sleep(0.3)
    try:
        for k in steps:
            F.send_press(s, k)
            time.sleep(0.35)
    finally:
        F.close_session(s)
        s.close()


if __name__ == "__main__":
    label = sys.argv[1] if len(sys.argv) > 1 else "idle"
    print("baseline:", free_heap())
    N = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    for i in range(1, N + 1):
        # full cycle: launch Petrel -> Wi-Fi -> Scan Wifi -> leave the app (BACK x9)
        run(["OK", "OK",
             "DOWN", "DOWN", "DOWN", "OK",                       # Apps -> GPIO
             "DOWN", "DOWN", "DOWN", "DOWN", "DOWN",
             "DOWN", "DOWN", "DOWN", "DOWN", "OK",               # -> Petrel
             "OK", "OK",                                         # Wi-Fi hub -> Scan
             "BACK", "BACK", "BACK", "BACK", "BACK", "BACK",
             "BACK", "BACK", "BACK", "BACK", "BACK"])            # leave the app
        time.sleep(12)
        f, mn = free_heap()
        print(f"iter {i:2d} [{label}]: free={f} min_since_boot={mn}")
