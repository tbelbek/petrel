#!/usr/bin/env python3
"""hs_to_pcap.py - turn petrel P5 `HSFRAME:<hex>` serial output into a .pcap.

The firmware (RTL8720dn-firmware.ino, CAPTURE / HSGRAB) streams each captured
EAPOL frame as a full 802.11 frame (no FCS) on one `HSFRAME:<hex>` line, ending
with `HSDONE:<count>`. This rebuilds those bytes into a libpcap file with
LINKTYPE_IEEE802_11 (105) so Wireshark / hcxpcapngtool can parse the 4-way.

Usage:
    # serialize the board's USB (CH340) output to a log first, e.g.:
    #   cat /dev/cu.usbserial-XXXX > capture.log
    python3 hs_to_pcap.py capture.log out.pcap

    # then:
    hcxpcapngtool -o hash.hc22000 out.pcap     # pcap -> hashcat 22000
    hashcat -m 22000 hash.hc22000 wordlist.txt

    # or, straight from the live port (needs pyserial):
    python3 hs_to_pcap.py --serial /dev/cu.usbserial-XXXX out.pcap

Options:
    --strip-fcs   drop the trailing 4 bytes (FCS) from every frame, if your
                  driver's raw buffer happens to include the CRC.
"""
import argparse
import re
import struct
import sys

# libpcap magic for microsecond timestamps + LINKTYPE_IEEE802_11
PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_IEEE802_11 = 105
SNAP_LEN = 65535

HSFRAME_RE = re.compile(r'HSFRAME:([0-9a-fA-F]+)')
HSDONE_RE = re.compile(r'HSDONE:(\d+)')


def parse_frames(text, strip_fcs=False):
    frames = []
    for line in text.splitlines():
        for m in HSFRAME_RE.finditer(line):
            h = m.group(1)
            if len(h) % 2:
                continue
            data = bytes.fromhex(h)
            if strip_fcs and len(data) > 4:
                data = data[:-4]
            if data:
                frames.append(data)
    return frames


def write_pcap(frames, out_path):
    with open(out_path, 'wb') as f:
        # global header: magic, major, minor, thiszone, sigfigs, snaplen, network
        f.write(struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, SNAP_LEN, LINKTYPE_IEEE802_11))
        # timestamps: order-preserving, ~1ms apart so Wireshark shows a sane sequence.
        base = 1700000000
        for i, data in enumerate(frames):
            ts_sec = base + i // 1000
            ts_usec = (i % 1000) * 1000
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
            f.write(data)


def read_serial(port, baud):
    try:
        import serial  # pyserial
    except ImportError:
        sys.exit("pyserial not installed; `pip install pyserial` or use `cat <port> > log`")
    buf = []
    with serial.Serial(port, baud, timeout=1) as ser:
        print(f"reading {port} @ {baud}; Ctrl-C to stop (writing on HSDONE)", file=sys.stderr)
        try:
            while True:
                line = ser.readline()
                if not line:
                    continue
                s = line.decode('ascii', 'replace')
                if 'HSFRAME:' in s:
                    buf.append(s)
                if 'HSDONE:' in s:
                    buf.append(s)
                    return '\n'.join(buf)
        except KeyboardInterrupt:
            return '\n'.join(buf)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('input', nargs='?', help='serial log containing HSFRAME lines')
    ap.add_argument('output', help='pcap to write')
    ap.add_argument('--serial', metavar='PORT', help='read live from a serial port instead of a file')
    ap.add_argument('--baud', type=int, default=115200)
    ap.add_argument('--strip-fcs', action='store_true')
    args = ap.parse_args()

    if args.serial:
        text = read_serial(args.serial, args.baud)
    elif args.input:
        with open(args.input, 'r', errors='replace') as f:
            text = f.read()
    else:
        ap.error('give an input log file, or --serial PORT')

    frames = parse_frames(text, strip_fcs=args.strip_fcs)
    if not frames:
        sys.exit('no HSFRAME lines found — did the capture trigger a 4-way?')
    write_pcap(frames, args.output)
    print(f"wrote {len(frames)} frame(s) -> {args.output} (linktype {LINKTYPE_IEEE802_11})")


if __name__ == '__main__':
    main()
