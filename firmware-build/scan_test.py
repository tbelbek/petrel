#!/usr/bin/env python3
"""M0.3 board-side test: SCAN, then LISTB -> decode DP_SCAN_AP binary frames,
cross-check SSID set against the legacy ASCII LIST. Runs over CH340.

Usage: scan_test.py [port] [baud]
"""
import sys, time, serial
from sniff_test import Dec

DP_SCAN_AP = 0x10

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    ser = serial.Serial(port, baud, timeout=0.3)
    ser.dtr = False; ser.rts = False; time.sleep(2.0); ser.reset_input_buffer()

    # 1. scan, wait for SCAN:OK (ASCII on CH340)
    ser.write(b"SCAN\n"); ser.flush()
    buf = b""; t0 = time.time()
    while time.time() - t0 < 10:
        buf += ser.read(4096)
        if b"SCAN:OK" in buf or b"SCAN:FAIL" in buf:
            break
    print("scan:", "OK" if b"SCAN:OK" in buf else ("FAIL" if b"SCAN:FAIL" in buf else "timeout"))
    time.sleep(0.3); ser.reset_input_buffer()

    # 2. binary list
    d = Dec()
    ser.write(b"LISTB\n"); ser.flush(); time.sleep(1.5)
    for b in ser.read(65536): d.feed(b)
    aps = [p for (t, p) in d.frames if t == DP_SCAN_AP]
    bin_rows = []
    total = None
    for p in aps:
        if len(p) < 2: continue
        idx, tot = p[0], p[1]
        total = tot
        if tot == 0:
            continue
        bssid = ':'.join(f'{x:02X}' for x in p[2:8])
        ch, sec = p[8], p[9]
        rssi = int.from_bytes(p[10:12], 'little', signed=True)
        sl = p[12]; ssid = bytes(p[13:13 + sl]).decode('utf-8', 'replace')
        bin_rows.append((idx, ssid, bssid, ch, sec, rssi))
    print(f"LISTB: {len(aps)} DP_SCAN_AP frames, total={total}, bad_crc={d.bad}")
    for r in bin_rows[:6]:
        print(f"  [{r[0]}] {r[1]!r} {r[2]} ch{r[3]} sec{r[4]} {r[5]}dBm")

    # 3. ASCII LIST cross-check
    ser.reset_input_buffer()
    ser.write(b"LIST\n"); ser.flush(); time.sleep(1.5)
    atxt = ser.read(65536).decode('utf-8', 'replace')
    ascii_ssids = []
    for line in atxt.splitlines():
        if line.startswith("AP:"):
            parts = line.split('|')
            if len(parts) >= 2:
                ascii_ssids.append(parts[1])
    ser.close()

    bin_ssids = [r[1] for r in bin_rows]
    print(f"ASCII LIST: {len(ascii_ssids)} rows")
    match = (len(bin_ssids) == len(ascii_ssids) and sorted(bin_ssids) == sorted(ascii_ssids))
    idx_ok = all(bin_rows[i][0] == i for i in range(len(bin_rows)))
    print(f"ssid_set_match={match} idx_sequential={idx_ok} bad_crc={d.bad}")
    ok = d.bad == 0 and match and idx_ok and total is not None
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
