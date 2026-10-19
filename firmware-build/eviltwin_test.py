#!/usr/bin/env python3
"""M3 evil-twin DRY control-plane test (CH340). Proves the FSM cycles DEAUTH<->PORTAL with the
REAL target SSID carried as DATA (logged "would clone/deauth"), transmits NOTHING, and STOP
releases the radio. The LIVE path (real clone AP + portal + deauth) is owner-verified in the lab.

Usage: eviltwin_test.py [port] [bssid-12hex] [ssid] [ch]"""
import serial, time, sys

PORT  = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220"
BSSID = sys.argv[2] if len(sys.argv) > 2 else "7C7716940911"
SSID  = sys.argv[3] if len(sys.argv) > 3 else "TestTwin"
CH    = sys.argv[4] if len(sys.argv) > 4 else "2"

p = serial.Serial(PORT, 115200, timeout=0.3)
p.dtr = False; p.rts = False; time.sleep(2.0); p.reset_input_buffer()
p.write(b"HELLO\n"); p.flush(); time.sleep(0.5)
print("alive:", "IDENT" in p.read(2048).decode(errors="replace"))

cmd = f"EVILTWIN START {BSSID} {SSID} {CH}\n"   # no LIVE token -> DRY
print(">>>", cmd.strip())
p.reset_input_buffer(); p.write(cmd.encode()); p.flush()
t0 = time.time(); buf = b""
while time.time() - t0 < 26:                     # ~2 cycles at burst4s+dwell10s
    buf += p.read(4096)
lines = [l.strip() for l in buf.decode(errors="replace").splitlines()
         if l.strip().startswith("EVILTWIN")]
for l in lines: print("  ", l)

p.reset_input_buffer(); p.write(b"EVILTWIN STATUS\n"); p.flush(); time.sleep(0.6)
print("  STATUS:", p.read(2048).decode(errors="replace").strip()[:90])
p.reset_input_buffer(); p.write(b"EVILTWIN STOP\n"); p.flush(); time.sleep(0.8)
rel = p.read(2048).decode(errors="replace").strip()
print("  STOP:", rel[:60])

# radio released even though we only ran dry?
p.reset_input_buffer(); p.write(f"PMFSCAN {CH} 2\n".encode()); p.flush(); time.sleep(3.5)
pmf = p.read(4096).decode(errors="replace")
p.close()

started = any("started" in l and "DRY" in l for l in lines)
ssid_ok = any(f'ssid="{SSID}"' in l for l in lines)            # SSID carried as data, correct
would_deauth = sum("would deauth" in l for l in lines)
would_clone  = sum("would clone" in l for l in lines)
no_rf = all("clone up" not in l for l in lines)                # DRY never brings the AP up
released = "released" in rel
radio_free = "PMF:" in pmf
print(f"\nstarted_dry={started} ssid_as_data_ok={ssid_ok} would_deauth={would_deauth} "
      f"would_clone={would_clone} cycled={would_clone>=1 and would_deauth>=2} no_onair={no_rf} "
      f"released={released} radio_free={radio_free}")
ok = (started and ssid_ok and would_clone >= 1 and would_deauth >= 2 and no_rf
      and released and radio_free)
print("RESULT:", "PASS" if ok else "CHECK")
