#!/usr/bin/env python3
"""M0.2 hardware test: arm SNIFF over CH340, decode DP_FRAME binary, report.

Mirrors common/petrel_proto.h on the host side. Verifies: frames arrive, CRC16 is
valid, record layout (ts|origlen|caplen|raw 802.11) is sane, truncation visible,
and the board stays alive after STOP.
"""
import sys, time, serial

SOF, VER = 0xA5, 0x01
DP_FRAME, DP_FRAME_DROP = 0x20, 0x21

def crc16(data):
    c = 0xFFFF
    for b in data:
        c = (c ^ (b << 8)) & 0xFFFF
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
    return c

class Dec:
    def __init__(self):
        self.reset(); self.bad = 0; self.frames = []
    def reset(self):
        self.st = 0; self.buf = bytearray(); self.ln = 0; self.got = 0; self.crc = 0
    def feed(self, b):
        st = self.st
        if st == 0:                         # SOF
            if b == SOF:
                self.buf = bytearray([b]); self.st = 1
        elif st == 1:                       # VER
            if b != VER: self.bad += 1; self.reset(); return
            self.buf.append(b); self.st = 2
        elif st == 2:                       # TYPE
            self.type = b; self.buf.append(b); self.st = 3
        elif st == 3:                       # LEN0
            self.ln = b; self.buf.append(b); self.st = 4
        elif st == 4:                       # LEN1
            self.ln |= b << 8; self.buf.append(b)
            if self.ln > 1024: self.bad += 1; self.reset(); return
            self.got = 0; self.st = 5 if self.ln else 6
        elif st == 5:                       # PAYLOAD
            self.buf.append(b); self.got += 1
            if self.got >= self.ln: self.st = 6
        elif st == 6:                       # CRC0
            self.crc = b; self.st = 7
        elif st == 7:                       # CRC1
            self.crc |= b << 8
            if self.crc == crc16(self.buf):
                self.frames.append((self.type, bytes(self.buf[5:])))
            else:
                self.bad += 1
            self.reset()

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbserial-20220"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    ch   = sys.argv[3] if len(sys.argv) > 3 else "6"
    secs = float(sys.argv[4]) if len(sys.argv) > 4 else 6.0
    ser = serial.Serial(port, baud, timeout=0.2)
    ser.dtr = False; ser.rts = False; time.sleep(0.3); ser.reset_input_buffer()
    d = Dec()
    ser.write(f"SNIFF START {ch}\n".encode()); ser.flush()
    t0 = time.time()
    while time.time() - t0 < secs:
        chunk = ser.read(4096)
        for b in chunk: d.feed(b)
    ser.write(b"SNIFF STOP\n"); ser.flush(); time.sleep(0.4)
    for b in ser.read(8192): d.feed(b)

    frame = [f for f in d.frames if f[0] == DP_FRAME]
    drop  = [f for f in d.frames if f[0] == DP_FRAME_DROP]
    other = [f for f in d.frames if f[0] not in (DP_FRAME, DP_FRAME_DROP)]
    print(f"window={secs}s ch={ch}  DP_FRAME={len(frame)} DP_FRAME_DROP={len(drop)} "
          f"other={len(other)} bad_crc/resync={d.bad}")
    trunc = 0
    for i, (_, p) in enumerate(frame[:4]):
        ts = int.from_bytes(p[0:4], "little"); orig = int.from_bytes(p[4:6], "little")
        cap = int.from_bytes(p[6:8], "little"); raw = p[8:]
        fc = raw[0] if raw else 0; ftype = (fc >> 2) & 3
        print(f"  frame[{i}] ts={ts} orig={orig} cap={cap} rawlen={len(raw)} "
              f"fc=0x{fc:02x} type={['mgmt','ctrl','data','ext'][ftype]}")
        assert cap == len(raw), f"caplen {cap} != raw {len(raw)}"
        assert cap <= orig, f"caplen {cap} > origlen {orig}"
    for _, p in frame:
        if int.from_bytes(p[6:8], "little") < int.from_bytes(p[4:6], "little"): trunc += 1
    if drop:
        dc = int.from_bytes(drop[-1][1][0:4], "little"); print(f"  last drop count = {dc}")
    print(f"  truncated(cap<orig) frames = {trunc}")

    # liveness: board answers HELLO after STOP (reply goes to Serial too)
    ser.reset_input_buffer(); ser.write(b"HELLO\n"); ser.flush(); time.sleep(0.6)
    alive = ser.read(4096).decode(errors="replace")
    ser.close()
    ident = "IDENT" in alive
    print(f"  post-stop HELLO -> {'IDENT ok (alive)' if ident else 'NO IDENT: ' + alive[:80]!r}")
    ok = len(frame) > 0 and ident
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
