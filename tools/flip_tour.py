#!/usr/bin/env python3
"""Drive the Petrel app once and screenshot every function (screen-control tour)."""
import sys, time
sys.path.insert(0, ".")
import flipctl as F

T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/tour"
import os
os.makedirs(T, exist_ok=True)

s = F.connect()
F.send(s, b"\xA2\x01\x00")  # keep the screen stream running for the whole tour
time.sleep(0.4)


def shot(name):
    time.sleep(0.5)
    d = F.grab(s, 1.5)
    if d:
        F.png(f"{T}/{name}.png", d)
        print("  shot", name)
    else:
        print("  !! NO FRAME", name)


def press(k):
    F.send_press(s, k)
    time.sleep(0.4)


print("== main card menu ==")
shot("00_main_wifi")
press("RIGHT"); shot("01_main_ble")
press("DOWN");  shot("02_main_exit")
press("LEFT");  shot("03_main_help")
press("UP");    shot("04_main_wifi_again")

print("== Wi-Fi hub ==")
press("OK");    shot("10_wifi_hub")

print("== Scan Wifi (busy screen) ==")
press("OK")
shot("11_scan_busy")      # new animated busy view while scanning
time.sleep(9)
shot("12_after_scan")     # back on the hub

print("== List Wifi ==")
press("DOWN"); press("OK"); shot("13_wifi_list")
press("BACK")

print("== Channel Map ==")
# hub: items Scan/List/ChannelMap/CreateAP/SendBeacon/LoadPortal -> selection is List(1)
press("DOWN"); press("OK"); shot("14_chanmap")
press("BACK")

print("== Create AP ==")
press("DOWN"); press("OK"); shot("15_create_ap")
press("BACK")

print("== Send Beacon ==")
press("DOWN"); press("OK"); shot("16_beacon_list")
press("BACK"); press("BACK")

print("== BLE hub ==")
press("RIGHT"); press("OK"); shot("20_ble_hub")
press("BACK")

print("== Help ==")
press("LEFT"); press("DOWN"); press("OK"); shot("30_help")
press("BACK")
press("BACK")

print("== back at main; cards ==")
shot("99_final")
s.close()
print("done ->", T)
