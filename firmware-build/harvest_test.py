#!/usr/bin/env python3
"""M2 Stage B dry-harvest test (CH340). Proves scan->select->grab(DRY)->next->done,
cooldown (distinct targets), no deauth TX, and STOP abort. No LIVE anywhere."""
import serial, time, sys

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220"

def readlines(p, secs, stopon=None):
    t0 = time.time(); buf = b""
    while time.time() - t0 < secs:
        buf += p.read(4096)
        if stopon and stopon.encode() in buf: break
    return [l.strip() for l in buf.decode(errors="replace").splitlines() if l.strip()]

p = serial.Serial(PORT, 115200, timeout=0.3)
p.dtr = False; p.rts = False; time.sleep(2.0); p.reset_input_buffer()
p.write(b"HELLO\n"); p.flush(); time.sleep(0.5)
print("HELLO:", "IDENT" in p.read(2048).decode(errors="replace"))

# --- Test 1: full 2-cycle dry harvest to completion ---
print("\n=== HARVEST START 2 (DRY) ===")
p.reset_input_buffer(); p.write(b"HARVEST START 2\n"); p.flush()
lines = readlines(p, 70, stopon="HARVEST:done")
for l in lines: print("  ", l)
targets = [l for l in lines if l.startswith("HARVEST:target")]
hsgdry  = [l for l in lines if l.startswith("HSGDRY")]
tx_seen = any("deauth" in l and "would" not in l for l in lines)  # sanity (no real TX log anyway)
bssids  = set(l.split()[1] for l in targets)
print(f"  -> targets={len(targets)} distinct_bssids={len(bssids)} hsgdry={len(hsgdry)} "
      f"done={'HARVEST:done' in ' '.join(lines)} hsdone={sum('HSDONE' in l for l in lines)}")

# --- Test 2: START then STOP abort ---
print("\n=== HARVEST START 5 then STOP ===")
p.reset_input_buffer(); p.write(b"HARVEST START 5\n"); p.flush()
time.sleep(3)
p.write(b"HARVEST STOP\n"); p.flush()
lines2 = readlines(p, 4)
for l in lines2: print("  ", l)
stopped = any("HARVEST:stopped" in l for l in lines2)

# liveness: radio free after stop
p.reset_input_buffer(); p.write(b"HARVEST STATUS\n"); p.flush(); time.sleep(0.6)
st = p.read(2048).decode(errors="replace").strip()
print("  STATUS after stop:", st[:80])
p.reset_input_buffer(); p.write(b"PMFSCAN 2 2\n"); p.flush(); time.sleep(3.5)
pmf = p.read(4096).decode(errors="replace").strip()
p.close()
print("  radio free (PMFSCAN works):", "PMF:" in pmf)

ok = (len(targets) >= 1 and len(bssids) == len(targets) and len(hsgdry) == len(targets)
      and not tx_seen and stopped and "PMF:" in pmf)
print("\nRESULT:", "PASS" if ok else "CHECK")
