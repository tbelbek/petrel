#!/usr/bin/env python3
"""Run each Tools action from the app, screenshot the busy screen and the result."""
import os, sys, time
sys.path.insert(0, ".")
import flipctl as F

T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/act"
os.makedirs(T, exist_ok=True)
s = F.connect()


def p(k, w=0.4):
    F.send_press(s, k)
    time.sleep(w)


def cap(name, w=2.0, tries=3):
    for _ in range(tries):
        time.sleep(0.4)
        d = F.grab(s, w)
        if d:
            F.png(f"{T}/{name}.png", d)
            print("  ", name)
            return True
    print("  NOFRAME", name)
    return False


def start_stream():
    F.send(s, b"\xA2\x01\x00")
    time.sleep(0.3)


# --- reach the Tools list ---
start_stream()
cap("00_before")
p("OK", 0.7)          # Wi-Fi hub (Scan Wifi selected)
p("DOWN")             # List Wifi
p("OK", 0.7)          # the scanned list
p("OK", 0.7)          # AP info
cap("01_apinfo")
p("LEFT", 0.7)        # Edit -> attack config
cap("02_attackcfg")
p("DOWN"); p("DOWN"); p("DOWN")   # to the Tools row
p("OK", 0.8)          # Tools list
cap("03_tools")
print("=== running each tool (DOWN xN then OK) ===")


def run_tool(downs, name, wait):
    # the Tools list selection starts at the top; walk to the item
    for _ in range(downs):
        p("DOWN", 0.22)
    p("OK", 0.3)
    cap(name + "_busy", 1.5)
    time.sleep(wait)
    cap(name + "_result", 2.0)
    cap(name + "_after", 1.2)


# order: 0 Capture HS,1 Grab HS,2 PMKID,3 PMKID grab,4 clientless,5 CAPSTOP,6 Audit,
#        7 PMF,8 STASCAN,9 Deauth+,10 RUN,11 STOP,12 Hop,13 Stop/clear
run_tool(7, "07_pmf", 7)         # PMF/WPA3 scan
run_tool(1, "08_stascan", 10)    # STASCAN (now at 7 -> +1)
run_tool(1, "12_channel_hop", 1) # hop on
cap("zz_final", 2.0)
print("done; app still running?" )
F.close_session(s)
s.close()
