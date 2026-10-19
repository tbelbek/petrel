#!/usr/bin/env python3
"""wardrive.py — wardriving over the board's existing scan path (reuses M1 SCAN/LISTB/DP_SCAN_AP;
does NOT fork a new scan). Loops scan -> accumulate APs (dedup by BSSID, keep strongest) -> write a
WiGLE-compatible CSV. GPS is HARDWARE the board/host doesn't have here: pass --gps-port <NMEA serial>
to tag real coordinates, else rows are tagged 0,0 (upload-valid but not geolocated) so the owner can
run it mobile with a GPS puck later.

Usage: wardrive.py [--port CH340] [--out war.csv] [--loops N] [--gps-port /dev/cu.usbserial-GPS]
"""
import sys, time, argparse, datetime, serial
from sniff_test import Dec

DP_SCAN_AP = 0x10

def authmode(sec):
    # board security int -> a reasonable WiGLE AuthMode string (owner can refine per RTW enum)
    if sec == 0: return "[ESS]"
    if sec & 0x00400000 or sec >= 4: return "[WPA2-PSK-CCMP][ESS]"
    return "[WPA-PSK][ESS]"

def read_gps(gps):
    # minimal NMEA RMC/GGA lat/lon parse; returns (lat, lon) or (0.0, 0.0)
    if not gps: return (0.0, 0.0)
    try:
        for _ in range(20):
            ln = gps.readline().decode(errors="replace").strip()
            if ln.startswith("$GPRMC") or ln.startswith("$GNRMC"):
                f = ln.split(",")
                if len(f) > 6 and f[2] == "A":
                    lat = int(f[3][:2]) + float(f[3][2:]) / 60.0; lat *= -1 if f[4] == "S" else 1
                    lon = int(f[5][:3]) + float(f[5][3:]) / 60.0; lon *= -1 if f[6] == "W" else 1
                    return (lat, lon)
    except Exception:
        pass
    return (0.0, 0.0)

def scan_once(ser, dec):
    ser.reset_input_buffer()
    ser.write(b"SCAN\n"); ser.flush()
    t0 = time.time(); buf = b""
    while time.time() - t0 < 9:
        buf += ser.read(4096)
        if b"SCAN:OK" in buf or b"SCAN:FAIL" in buf: break
    time.sleep(0.2); ser.reset_input_buffer()
    ser.write(b"LISTB\n"); ser.flush(); time.sleep(1.5)
    for b in ser.read(65536): dec.feed(b)
    rows = []
    for t, p in dec.frames:
        if t != DP_SCAN_AP or len(p) < 13: continue
        if p[1] == 0: continue
        sl = p[12]
        if len(p) < 13 + sl: continue
        bssid = ':'.join(f'{x:02X}' for x in p[2:8])
        ch, sec = p[8], p[9]
        rssi = int.from_bytes(p[10:12], 'little', signed=True)
        ssid = bytes(p[13:13 + sl]).decode('utf-8', 'replace')
        rows.append((bssid, ssid, ch, sec, rssi))
    dec.frames.clear()
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/cu.usbserial-20220")
    ap.add_argument("--out", default="war.csv")
    ap.add_argument("--loops", type=int, default=3)
    ap.add_argument("--gps-port", default=None)
    a = ap.parse_args()
    ser = serial.Serial(a.port, 115200, timeout=0.3)
    ser.dtr = False; ser.rts = False; time.sleep(2.0); ser.reset_input_buffer()
    gps = serial.Serial(a.gps_port, 9600, timeout=0.3) if a.gps_port else None
    dec = Dec()
    seen = {}  # bssid -> (ssid, ch, sec, rssi, lat, lon, ts)
    for i in range(a.loops):
        lat, lon = read_gps(gps)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = scan_once(ser, dec)
        for bssid, ssid, ch, sec, rssi in rows:
            if bssid not in seen or rssi > seen[bssid][3]:
                seen[bssid] = (ssid, ch, sec, rssi, lat, lon, ts)
        print(f"loop {i+1}/{a.loops}: {len(rows)} APs this scan, {len(seen)} unique total, gps=({lat:.5f},{lon:.5f})")
    ser.close()
    if gps: gps.close()
    with open(a.out, "w") as f:
        f.write("WigleWifi-1.4,appRelease=Petrel,model=BW16,release=v2,device=RTL8720DN,"
                "display=petrel,board=bw16,brand=petrel\n")
        f.write("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
                "AltitudeMeters,AccuracyMeters,Type\n")
        for bssid, (ssid, ch, sec, rssi, lat, lon, ts) in seen.items():
            ssid_c = ssid.replace(",", " ")
            f.write(f"{bssid},{ssid_c},{authmode(sec)},{ts},{ch},{rssi},{lat},{lon},0,0,WIFI\n")
    print(f"wrote {len(seen)} unique APs to {a.out} (WiGLE CSV)")
    if not a.gps_port:
        print("NOTE: no --gps-port -> coords are 0,0. Attach a GPS puck + pass --gps-port for geolocated rows.")

if __name__ == "__main__":
    main()
