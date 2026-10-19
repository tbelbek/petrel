#!/usr/bin/env python3
"""Dry-run verification over CH340: confirm every new offensive command is recognized + parses
(via its error/usage path — NO firing, no third party) and the board never crashes; plus a
regression of the already-verified CH340-visible core (CHAN collision fix, scan, WIDS, LED)."""
import serial, time, sys

p = serial.Serial(sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220", 115200, timeout=0.3)
p.dtr = False; p.rts = False; time.sleep(2.5); p.reset_input_buffer()

def ask(cmd, wait=0.6):
    p.reset_input_buffer(); p.write((cmd + "\n").encode()); p.flush(); time.sleep(wait)
    return p.read(4096).decode(errors="replace")

ok = True
print("== OFFENSIVE recognition + parse (error paths, NO firing) ==")
for cmd, exp in [("CHANINTERF", "ERROR: CHANINTERF"), ("BBH xx", "ERROR: BBH"),
                 ("GATTRW", "ERROR: GATTRW"), ("HOSTSCAN", "ERROR: HOSTSCAN"),
                 ("ARPSPOOF", "ERROR: ARPSPOOF"), ("RESPONDER", "ERROR: RESPONDER")]:
    out = ask(cmd); good = exp in out
    ok &= good
    print(f"  {cmd:12} -> {'recognized' if good else 'FAIL: ' + out.strip()[:50]}")

print("== REGRESSION (CH340-visible core still works) ==")
alive = "IDENT" in ask("HELLO"); ok &= alive; print(f"  HELLO alive: {alive}")
chan = "CHAN:req=6" in ask("CHAN 6"); ok &= chan; print(f"  CHAN 6 (collision fix): {chan}")
led = "LED:r1 g0 b0" in ask("LED 1 0 0"); ok &= led; print(f"  LED: {led}")
ask("LED OFF"); ask("LED ON")
scan = "SCAN:OK" in ask("SCAN", 7); ok &= scan; print(f"  SCAN: {scan}")
w1 = "WIDS:started" in ask("WIDS START 6"); w2 = "WIDS:stopped" in ask("WIDS STOP")
ok &= (w1 and w2); print(f"  WIDS start/stop: {w1 and w2}")
# final liveness: board survived all of the above without a wedge
final = "IDENT" in ask("HELLO"); ok &= final; print(f"  final alive (no crash): {final}")

p.close()
print("\nRESULT:", "PASS — all recognized + parse + no crash" if ok else "CHECK")
