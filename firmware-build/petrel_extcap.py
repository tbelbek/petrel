#!/usr/bin/env python3
"""petrel_extcap.py — Wireshark extcap for the Petrel BW16 live 802.11 sniffer.

Live-captures the board's binary DP_FRAME stream over CH340 and feeds Wireshark a
libpcap stream (DLT 105, LINKTYPE_IEEE802_11, no FCS). Self-contained (droppable
into Wireshark's extcap dir). Timestamps are HOST wall-clock at read time (the
board's ts is millis-since-boot, useless as an absolute time).

Install: copy this file to the Wireshark extcap dir (Help > About > Folders >
"Extcap path"), make it executable, restart Wireshark. "Petrel BW16 sniffer"
appears in the interface list. Pick a channel in its gear/config.

Standalone test (no Wireshark):
  ./petrel_extcap.py --extcap-interface petrelrtl --capture \
      --fifo /tmp/d.pcap --channel 6 --port /dev/cu.usbserial-20220
  # Ctrl-C to stop; then: tshark -r /tmp/d.pcap   (or scapy/python)
"""
import sys, os, time, struct, argparse, signal, serial

# ---- petrel_proto decoder (mirror of common/petrel_proto.h; inlined to stay single-file) ----
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
        self.reset(); self.bad = 0
    def reset(self):
        self.st = 0; self.buf = bytearray(); self.ln = 0; self.got = 0; self.crc = 0
    def feed(self, b):
        st = self.st
        if st == 0:
            if b == SOF:
                self.buf = bytearray([b]); self.st = 1
        elif st == 1:
            if b != VER: self.bad += 1; self.reset(); return None
            self.buf.append(b); self.st = 2
        elif st == 2:
            self.type = b; self.buf.append(b); self.st = 3
        elif st == 3:
            self.ln = b; self.buf.append(b); self.st = 4
        elif st == 4:
            self.ln |= b << 8; self.buf.append(b)
            if self.ln > 1024: self.bad += 1; self.reset(); return None
            self.got = 0; self.st = 5 if self.ln else 6
        elif st == 5:
            self.buf.append(b); self.got += 1
            if self.got >= self.ln: self.st = 6
        elif st == 6:
            self.crc = b; self.st = 7
        elif st == 7:
            self.crc |= b << 8
            ok = (self.crc == crc16(self.buf))
            t, payload = self.type, bytes(self.buf[5:])
            if not ok: self.bad += 1
            self.reset()
            return (t, payload) if ok else None
        return None

# ---- pcap (libpcap, DLT 105, host-clock timestamps) ----
PCAP_MAGIC = 0xA1B2C3D4
SNAPLEN = 256          # == board FRM_SLOT caplen cap
LINKTYPE_IEEE802_11 = 105

def pcap_global_header():
    # magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
    return struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_IEEE802_11)

def pcap_record(raw, origlen):
    t = time.time()
    sec = int(t); usec = int((t - sec) * 1_000_000)
    incl = len(raw)
    if incl > SNAPLEN: incl = SNAPLEN; raw = raw[:SNAPLEN]
    # orig_len must be >= incl_len; origlen is the on-air length (>= caplen by construction)
    orig = origlen if origlen >= incl else incl
    return struct.pack('<IIII', sec, usec, incl, orig) + raw

# ---- extcap discovery output ----
def extcap_interfaces():
    print("extcap {version=1.0}{help=https://github.com/tbelbek/petrel}")
    print("interface {value=petrelrtl}{display=Petrel BW16 sniffer}")

def extcap_dlts():
    print("dlt {number=%d}{name=IEEE802_11}{display=802.11 (no FCS)}" % LINKTYPE_IEEE802_11)

def extcap_config():
    print("arg {number=0}{call=--channel}{display=Channel}{type=integer}"
          "{range=1,165}{default=6}{tooltip=802.11 channel to monitor}")
    print("arg {number=1}{call=--port}{display=Serial port (CH340)}{type=string}"
          "{default=/dev/cu.usbserial-20220}{tooltip=BW16 CH340 bulk port}")
    print("arg {number=2}{call=--baud}{display=Baud}{type=integer}{default=115200}")

# ---- capture ----
def do_capture(fifo, port, channel, baud, duration=0):
    ser = serial.Serial(port, baud, timeout=0.2)
    ser.dtr = False; ser.rts = False; time.sleep(0.3); ser.reset_input_buffer()
    stop = {"v": False}
    def _stop(*_):
        stop["v"] = True
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    f = open(fifo, "wb")
    t0 = time.time()
    try:
        f.write(pcap_global_header()); f.flush()
        ser.write(("SNIFF START %d\n" % channel).encode()); ser.flush()
        dec = Dec(); drops = 0; n = 0
        while not stop["v"] and (duration <= 0 or time.time() - t0 < duration):
            chunk = ser.read(4096)
            for b in chunk:
                r = dec.feed(b)
                if r is None:
                    continue
                t, payload = r
                if t == DP_FRAME and len(payload) >= 8:
                    origlen = int.from_bytes(payload[4:6], "little")
                    caplen = int.from_bytes(payload[6:8], "little")
                    raw = payload[8:8 + caplen]
                    f.write(pcap_record(raw, origlen)); f.flush()
                    n += 1
                elif t == DP_FRAME_DROP and len(payload) >= 4:
                    drops = int.from_bytes(payload[0:4], "little")
                    sys.stderr.write("petrel_extcap: board dropped %d frame(s)\n" % drops)
                    sys.stderr.flush()
    finally:
        try:
            ser.write(b"SNIFF STOP\n"); ser.flush()
        except Exception:
            pass
        ser.close(); f.close()
        sys.stderr.write("petrel_extcap: stopped (%d frames, %d drops, %d bad-crc)\n"
                         % (n, drops, dec.bad))

def main():
    ap = argparse.ArgumentParser(description="Petrel Wireshark extcap", add_help=True)
    ap.add_argument("--extcap-interfaces", action="store_true")
    ap.add_argument("--extcap-dlts", action="store_true")
    ap.add_argument("--extcap-config", action="store_true")
    ap.add_argument("--extcap-interface")
    ap.add_argument("--extcap-version")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--fifo")
    ap.add_argument("--channel", type=int, default=6)
    ap.add_argument("--port", default="/dev/cu.usbserial-20220")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--duration", type=int, default=0, help="test only: stop after N seconds (0=until signal)")
    a, _ = ap.parse_known_args()

    if a.extcap_interfaces:
        extcap_interfaces(); return 0
    if a.extcap_dlts:
        extcap_dlts(); return 0
    if a.extcap_config:
        extcap_config(); return 0
    if a.capture:
        if not a.fifo:
            sys.stderr.write("--capture requires --fifo\n"); return 1
        do_capture(a.fifo, a.port, a.channel, a.baud, a.duration); return 0
    ap.print_help(sys.stderr); return 0

if __name__ == "__main__":
    sys.exit(main())
