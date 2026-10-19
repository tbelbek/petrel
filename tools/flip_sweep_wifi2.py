#!/usr/bin/env python3
"""Sweep every Wi-Fi hub action; deterministic (re-enter the hub from the main menu each time)."""
import os, sys, time
sys.path.insert(0, ".")
import flipctl as F

T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/act2"
os.makedirs(T, exist_ok=True)
s = F.connect()
F.send(s, b"\xA2\x01\x00")
time.sleep(0.4)


def p(k, w=0.45):
    F.send_press(s, k)
    time.sleep(w)


def cap(n, w=2.0):
    time.sleep(0.5)
    d = F.grab(s, w)
    if d:
        F.png(f"{T}/{n}.png", d)
        print("  ", n)
    else:
        print("  NOFRAME", n)


# from the app main card menu (Wi-Fi selected)
ITEMS = [
    ("hub",          0, 1.2),
    ("scan",         1, 13),      # OK on Scan Wifi (item 0)
    ("list",         2, 2.5),     # List Wifi
    ("channelmap",   3, 2.5),
    ("createap",     4, 2.5),
    ("sendbeacon",   5, 2.5),
    ("loadportal",   6, 2.5),
]
for name, n, wait in ITEMS:
    p("OK", 0.8)                  # enter the Wi-Fi hub (selection resets to Scan Wifi)
    for _ in range(n - 1):
        p("DOWN", 0.25)
    p("OK", 0.3)                  # trigger the item
    cap(name, max(2.0, wait))
    time.sleep(max(0.0, wait - 2.0))
    p("BACK", 0.6)                # item -> hub
    p("BACK", 0.6)                # hub -> main card menu
F.close_session(s)
s.close()
print("done")
