#!/usr/bin/env python3
"""Full UI sweep: reach + trigger EVERY action in the Petrel app, screenshot each.

Deterministic: before every action we exit the app (BACK x N) and relaunch it from the
desktop (OK, OK, DOWN x3, OK, DOWN x9, OK) so the starting state is always identical.
"""
import os, sys, time
sys.path.insert(0, ".")
import flipctl as F

T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/full"
os.makedirs(T, exist_ok=True)
DOWN = "DOWN"

# reach-paths from a FRESH app (main card menu, Wi-Fi selected)
WIFI_HUB = ["OK"]
LIST = WIFI_HUB + ["DOWN", "OK"]
APINFO = LIST + ["OK"]
ATTACKCFG = APINFO + ["LEFT"]
TOOLS = ATTACKCFG + ["DOWN", "DOWN", "DOWN", "OK"]
BLE_HUB = ["RIGHT", "OK"]

# (name, parent_path, trigger_keys, wait_s_after_trigger)
ACTIONS = [
    ("cardnav_right",  [], [], 0.3),
    ("cardnav_down",   [], ["DOWN"], 0.3),
    ("cardnav_left",   [], ["LEFT"], 0.3),
    ("cardnav_up",     [], ["UP"], 0.3),
    ("wifi_hub",       [], WIFI_HUB, 1.0),
    ("scan_wifi",      WIFI_HUB, ["OK"], 12),          # busy screen + list fill
    ("list_wifi",      WIFI_HUB, ["DOWN", "OK"], 2),
    ("channel_map",    WIFI_HUB, ["DOWN", "DOWN", "OK"], 2),
    ("create_ap",      WIFI_HUB, ["DOWN", "DOWN", "DOWN", "OK"], 2),
    ("send_beacon",    WIFI_HUB, ["DOWN", "DOWN", "DOWN", "DOWN", "OK"], 2),
    ("load_portal",    WIFI_HUB, ["DOWN"] * 5 + ["OK"], 2),
    ("ap_info",        LIST,     ["OK"], 2),
    ("ap_deauth_btn",  APINFO,   ["OK"], 3),            # OK on the info screen = Deauth toggle
    ("attack_cfg",     APINFO,   ["LEFT"], 2),
    ("tools_menu",     ATTACKCFG, ["DOWN", "DOWN", "DOWN", "OK"], 2),
    ("tool_0_captureHS",   TOOLS, ["OK"], 12),
    ("tool_1_grabHS",      TOOLS, ["DOWN"] + ["OK"], 12),
    ("tool_2_pmkid",       TOOLS, ["DOWN"] * 2 + ["OK"], 12),
    ("tool_3_pkgrab",      TOOLS, ["DOWN"] * 3 + ["OK"], 12),
    ("tool_4_clientless",  TOOLS, ["DOWN"] * 4 + ["OK"], 12),
    ("tool_5_capstop",     TOOLS, ["DOWN"] * 5 + ["OK"], 3),
    ("tool_6_audit",       TOOLS, ["DOWN"] * 6 + ["OK"], 12),
    ("tool_7_pmf",         TOOLS, ["DOWN"] * 7 + ["OK"], 10),
    ("tool_8_stascan",     TOOLS, ["DOWN"] * 8 + ["OK"], 12),
    ("tool_9_deauthadd",   TOOLS, ["DOWN"] * 9 + ["OK"], 3),
    ("tool_10_deauthrun",  TOOLS, ["DOWN"] * 10 + ["OK"], 3),
    ("tool_11_deauthstop", TOOLS, ["DOWN"] * 11 + ["OK"], 3),
    ("tool_12_hop",        TOOLS, ["DOWN"] * 12 + ["OK"], 3),
    ("tool_13_stopclear",  TOOLS, ["DOWN"] * 13 + ["OK"], 3),
    ("ble_hub",        [], BLE_HUB, 1.0),
    ("ble_scan",       BLE_HUB, ["OK"], 12),
    ("ble_ibeacon_demo", BLE_HUB, ["DOWN", "OK"], 4),
    ("ble_ibeacon_uuid", BLE_HUB, ["DOWN", "DOWN", "OK"], 3),
    ("ble_badble_hid",   BLE_HUB, ["DOWN"] * 3 + ["OK"], 4),
    ("ble_badble_file",  BLE_HUB, ["DOWN"] * 4 + ["OK"], 4),
    ("ble_adv_hex",      BLE_HUB, ["DOWN"] * 5 + ["OK"], 3),
    ("ble_adv_replay",   BLE_HUB, ["DOWN"] * 6 + ["OK"], 4),
    ("ble_saved_adv",    BLE_HUB, ["DOWN"] * 7 + ["OK"], 3),
    ("help",           ["DOWN"], ["OK"], 2),
    ("createap_security", ["OK","DOWN","DOWN","DOWN","OK"], ["DOWN"], 1),
    ("createap_channel",  ["OK","DOWN","DOWN","DOWN","OK"], ["DOWN","DOWN","RIGHT"], 1),
    ("createap_portal",   ["OK","DOWN","DOWN","DOWN","OK"], ["DOWN","DOWN","DOWN","RIGHT"], 1),
    ("exit_app",       ["DOWN"], ["RIGHT", "OK"], 2),
]


def p(k, w=0.35):
    F.send_press(s, k)
    time.sleep(w)


def cap(name, w=1.6, tries=3):
    for _ in range(tries):
        time.sleep(0.35)
        d = F.grab(s, w)
        if d:
            F.png(f"{T}/{name}.png", d)
            return True
    return False


def reset_and_launch():
    """Exit the app (BACK x12) and relaunch it from the desktop -> deterministic state."""
    for _ in range(12):
        p("BACK", 0.12)
    time.sleep(0.5)
    p("OK", 0.6)                       # desktop menu
    p("OK", 0.9)                       # Apps
    p("DOWN"); p("DOWN"); p("DOWN"); p("OK", 0.9)   # GPIO
    for _ in range(9):
        p("DOWN", 0.18)
    p("OK", 1.3)                       # Petrel


s = F.connect()
F.send(s, b"\xA2\x01\x00")   # start the screen stream ONCE per session (restarting it
time.sleep(0.3)                # per action leaks the device's RAM -> OOM/crash)
only = sys.argv[1:] or None
try:
    for name, parent, trig, wait in ACTIONS:
        if only and name not in only:
            continue
        reset_and_launch()
        cap(name + "_home", 1.0)
        for k in parent:
            p(k, 0.35)
        for k in trig:
            p(k, 0.35)
        ok = cap(name + "_result", max(1.6, wait))
        print(f"{'ok ' if ok else 'NOF'} {name}")
        time.sleep(max(0.0, wait - 1.6))
finally:
    F.close_session(s)
    s.close()
print("done")
