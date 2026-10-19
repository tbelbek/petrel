#!/usr/bin/env python3
"""Wi-Fi deep-dive sweep of the Petrel app: walk every Wi-Fi function, screenshot each."""
import os, sys, time
sys.path.insert(0, ".")
import flipctl as F

T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/tour2"
os.makedirs(T, exist_ok=True)

s = F.connect()
F.send(s, b"\xA2\x01\x00")
time.sleep(0.4)


def shot(name, tries=2):
    for _ in range(tries):
        time.sleep(0.5)
        d = F.grab(s, 2.0)
        if d:
            F.png(f"{T}/{name}.png", d)
            print("  shot", name)
            return
    print("  !! NO FRAME", name)


def p(k, wait=0.4):
    F.send_press(s, k)
    time.sleep(wait)


print("=== Wi-Fi hub ===")
p("OK"); shot("01_hub")
print("=== Channel Map ===")
p("DOWN"); p("DOWN"); p("OK"); shot("02_chanmap")
p("RIGHT"); shot("03_chanmap_pan")
p("LEFT"); p("BACK"); shot("04_hub_back")
print("=== Create AP ===")
p("DOWN"); p("OK"); shot("05_createap")
p("DOWN"); p("DOWN"); p("DOWN"); p("DOWN"); shot("06_ca_loadportal_row")
p("OK"); shot("07_portal_list")
p("OK"); shot("08_portal_loaded")
p("BACK"); shot("09_hub")
print("=== List Wifi -> AP info ===")
p("UP"); p("UP"); p("DOWN"); p("OK"); shot("10_wifi_list")
p("OK"); shot("11_ap_info")
print("=== Info -> Deauth -> Attack config -> Tools ===")
p("OK"); shot("12_attack_cfg")
p("DOWN"); p("DOWN"); p("DOWN"); shot("13_tools_row")
p("OK"); shot("14_tools_list")
print("=== Tools: PMF/WPA3 scan (item 7) ===")
for _ in range(7): p("DOWN", 0.25)
shot("15_row_pmf")
p("OK"); shot("16_pmf_busy")
time.sleep(8); shot("17_pmf_result")
p("BACK"); shot("18_tools_back")
print("=== Tools: STASCAN (item 8) ===")
p("DOWN"); p("OK"); shot("19_sta_busy")
time.sleep(9); shot("20_sta_result")
p("BACK")
print("=== Tools: channel hop (item 12) ===")
# back at the tools list, selection is at item 8; go to 12
for _ in range(4): p("DOWN", 0.25)
p("OK"); shot("21_hop")
p("BACK")
print("=== Tools: Stop / clear (item 13) ===")
p("DOWN"); p("OK"); shot("22_stopclear")
print("done")
s.close()
