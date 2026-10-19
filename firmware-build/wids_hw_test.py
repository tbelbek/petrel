#!/usr/bin/env python3
"""M3 WIDS hardware test (CH340, listen-only). Verifies the monitor runs, processes
ambient frames, does NOT false-positive evil-twin on a legit multi-BSSID ESS (same
SSID on several BSSIDs), and the lifecycle (START/STATUS/STOP) + radio release.

Detection TRIGGERS (deauth-flood, RSN-downgrade) are proven by the host unit test
common/wids_test.c — the firmware never self-transmits to test a detector.

Usage: wids_hw_test.py [port] [channel]
"""
import serial, time, sys

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220"
CH = sys.argv[2] if len(sys.argv) > 2 else "2"

p = serial.Serial(PORT, 115200, timeout=0.3)
p.dtr = False; p.rts = False; time.sleep(2.0); p.reset_input_buffer()
p.write(b"HELLO\n"); p.flush(); time.sleep(0.5)
print("alive:", "IDENT" in p.read(2048).decode(errors="replace"))

print(f">>> WIDS START {CH}")
p.reset_input_buffer(); p.write(f"WIDS START {CH}\n".encode()); p.flush()
t0 = time.time(); buf = b""
while time.time() - t0 < 10:
    buf += p.read(4096)
lines = [l.strip() for l in buf.decode(errors="replace").splitlines() if l.strip()]
started = any(l.startswith("WIDS:started") for l in lines)
TYPES = ("DEAUTHFLOOD", "EVILTWIN", "BEACONFLOOD", "KARMA")
alerts = [l for l in lines if any(l.startswith("WIDS:" + t) for t in TYPES)]
evil = alerts  # in a normal environment ALL four detectors should stay silent (no false positive)
for l in lines:
    if l.startswith("WIDS") and "DUMP" not in l: print("  ", l)
for l in alerts: print("   FALSE-POSITIVE:", l)

p.reset_input_buffer(); p.write(b"WIDS STATUS\n"); p.flush(); time.sleep(0.6)
st = p.read(2048).decode(errors="replace").strip()
print("  STATUS:", st[:80])
frames = 0
for tok in st.replace("\n", " ").split():
    if tok.startswith("frames="):
        try: frames = int(tok.split("=")[1])
        except ValueError: pass

p.reset_input_buffer(); p.write(b"WIDS STOP\n"); p.flush(); time.sleep(0.6)
print("  STOP:", p.read(2048).decode(errors="replace").strip()[:60])

# radio released?
p.reset_input_buffer(); p.write(b"PMFSCAN %s 2\n" % CH.encode()); p.flush(); time.sleep(3.5)
pmf = p.read(4096).decode(errors="replace")
p.close()
radio_free = "PMF:" in pmf

print(f"\nstarted={started} frames={frames} evil_twin_false_positives={len(evil)} "
      f"radio_free_after_stop={radio_free}")
ok = started and frames > 0 and len(evil) == 0 and radio_free
print("RESULT:", "PASS" if ok else "CHECK")
