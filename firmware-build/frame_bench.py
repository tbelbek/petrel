#!/usr/bin/env python3
"""M0 transport throughput + integrity bench over CH340.

Sends FRAMEBENCH to the board, decodes the synthetic DP_FRAME stream, and checks:
sequence (ts == frame index), payload pattern raw[j]==(ts+j)&0xff, CRC (decoder),
and sustained throughput. The CRC/payload check is the point at 921600 — a bad clock
divisor shows up as CRC failures / corrupted payload, not just slower frames.

Usage: frame_bench.py [port] [baud] [count] [paylen]
"""
import sys, time, serial
from sniff_test import Dec, DP_FRAME

def main():
    port   = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220"
    baud   = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    count  = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
    paylen = int(sys.argv[4]) if len(sys.argv) > 4 else 256
    ser = serial.Serial(port, baud, timeout=0.5)
    ser.dtr = False; ser.rts = False; time.sleep(0.3); ser.reset_input_buffer()
    d = Dec()
    ser.write(f"FRAMEBENCH {count} {paylen}\n".encode()); ser.flush()
    t0 = None; last = time.time(); nbytes = 0; deadline = time.time() + 90
    while len([f for f in d.frames if f[0] == DP_FRAME]) < count and time.time() < deadline:
        chunk = ser.read(65536)
        if chunk:
            if t0 is None: t0 = time.time()
            nbytes += len(chunk); last = time.time()
            for b in chunk: d.feed(b)
        elif time.time() - last > 2:
            break
    ser.close()

    frames = [f for f in d.frames if f[0] == DP_FRAME]
    recv = len(frames); seq_ok = 0; pay_bad = 0
    for idx, (_, p) in enumerate(frames):
        ts = int.from_bytes(p[0:4], "little"); raw = p[8:]
        if ts == idx: seq_ok += 1
        if any(raw[j] != ((ts + j) & 0xff) for j in range(len(raw))): pay_bad += 1
    elapsed = (last - t0) if t0 else 0
    fps  = recv / elapsed if elapsed > 0 else 0
    kbps = nbytes / 1024 / elapsed if elapsed > 0 else 0
    print(f"baud={baud} sent={count} paylen={paylen}")
    print(f"received={recv} missing={count - recv} bad_crc/resync={d.bad} "
          f"seq_ok={seq_ok} payload_bad={pay_bad}")
    print(f"elapsed={elapsed:.3f}s  throughput={fps:.0f} frame/s  {kbps:.1f} KB/s  ({nbytes} bytes)")
    # integrity is the hard requirement; missing frames may be host-side OS buffer loss at high baud
    integrity = d.bad == 0 and pay_bad == 0 and seq_ok == recv
    print("INTEGRITY:", "OK" if integrity else "BAD",
          "| COMPLETE" if recv == count else f"| {count - recv} missing (host read?)")
    print("RESULT:", "PASS" if (integrity and recv == count) else
          ("INTEGRITY-OK/INCOMPLETE" if integrity else "FAIL"))
    return 0 if integrity else 1

if __name__ == "__main__":
    sys.exit(main())
