#!/usr/bin/env python3
"""flipctl - see and drive the Flipper Zero screen over USB RPC (no qFlipper needed).

Usage:
  flipctl.py shot  <out.png>                 capture the current screen
  flipctl.py key   <KEY> <TYPE>              one input event
  flipctl.py press <KEY>                     press + short-release
  flipctl.py drive <KEY[:TYPE]> ...          a sequence, then capture the last screen
                 [--shot <out.png>] [--settle 0.25]

KEYS: UP DOWN RIGHT LEFT OK BACK      TYPES: PRESS RELEASE SHORT LONG REPEAT

How it works
  * CLI handshake: "start_rpc_session\\r", then framing = [varint len][protobuf Main]
  * Main: 1 command_id, 20 start_screen_stream, 22 screen_frame, 23 send_input_event
  * ScreenFrame.data = 1024 B, SSD1306 PAGE layout: byte = (y//8)*128 + x, bit = y%8
"""
import signal
import struct
import sys
import time
import zlib

import serial

PORT = "/dev/cu.usbmodemflip_Uy0th11"
W, H = 128, 64
KEYS = {"UP": 0, "DOWN": 1, "RIGHT": 2, "LEFT": 3, "OK": 4, "BACK": 5}
TYPES = {"PRESS": 0, "RELEASE": 1, "SHORT": 2, "LONG": 3, "REPEAT": 4}
_cmd = [0]


def varint(n):
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        o.append(b | 0x80 if n else b)
        if not n:
            return bytes(o)


def rv(buf, i):
    s = v = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << s
        if not (b & 0x80):
            return v, i
        s += 7
    return None, i


def connect():
    s = serial.Serial(PORT, 115200, timeout=0.2, dsrdtr=False, write_timeout=5)
    time.sleep(0.5)
    s.reset_input_buffer()
    s.write(b"\r")
    time.sleep(0.4)
    s.read(8192)
    s.write(b"start_rpc_session\r")
    time.sleep(0.5)
    s.read(8192)
    s.reset_input_buffer()
    return s


def send(s, body):
    _cmd[0] += 1
    p = b"\x08" + varint(_cmd[0]) + body
    s.write(varint(len(p)) + p)
    s.flush()


def send_key(s, key, typ):
    k, t = KEYS[key.upper()], TYPES[typ.upper()]
    send(s, bytes([0xBA, 0x01, 0x04, 0x08, k, 0x10, t]))  # Main.send_input_event{key,type}


def send_press(s, key, pause=0.04):
    """A real button press = PRESS + SHORT + RELEASE (a lone SHORT is swallowed by the
    desktop animation; the full triple is what the UI acts on)."""
    send_key(s, key, "PRESS")
    time.sleep(pause)
    send_key(s, key, "SHORT")
    time.sleep(pause)
    send_key(s, key, "RELEASE")


def frame_data(payload):
    i = 0
    while i < len(payload):
        k, i = rv(payload, i)
        if k is None:
            return None
        f, w = k >> 3, k & 7
        if w == 2:
            ln, i = rv(payload, i)
            if ln is None or i + ln > len(payload):
                return None
            val = payload[i : i + ln]
            i += ln
            if f == 22:
                j = 0
                while j < len(val):
                    k2, j = rv(val, j)
                    f2, w2 = k2 >> 3, k2 & 7
                    if w2 == 2:
                        l2, j = rv(val, j)
                        if l2 is None or j + l2 > len(val):
                            return None
                        v2 = val[j : j + l2]
                        j += l2
                        if f2 == 1 and len(v2) == 1024:
                            return v2
                    elif w2 == 0:
                        _, j = rv(val, j)
                    else:
                        return None
        elif w == 0:
            _, i = rv(payload, i)
        else:
            return None
    return None


def png(path, d):
    raw = bytearray()
    for y in range(H):
        raw.append(0)
        for x in range(0, W, 8):
            b = 0
            for i in range(8):
                bit = (d[(y // 8) * 128 + (x + i)] >> (y % 8)) & 1
                b = (b << 1) | (0 if bit else 1)
            raw.append(b)

    def ch(t, dd):
        c = t + dd
        return struct.pack(">I", len(dd)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    open(path, "wb").write(
        b"\x89PNG\r\n\x1a\n"
        + ch(b"IHDR", struct.pack(">IIBBBBB", W, H, 1, 0, 0, 0, 0))
        + ch(b"IDAT", zlib.compress(bytes(raw)))
        + ch(b"IEND", b"")
    )


def grab(s, timeout=1.5):
    """Return the latest frame data seen within `timeout` (stream must be started)."""
    buf = bytearray()
    last = None
    t0 = time.time()
    while time.time() - t0 < timeout:
        c = s.read(4096)
        if c:
            buf += c
        i = 0
        while True:
            ln, j = rv(bytes(buf), i)
            if ln is None or j + ln > len(buf):
                break
            d = frame_data(bytes(buf[j : j + ln]))
            i = j + ln
            if d:
                last = d
        if i:
            del buf[:i]
    return last


# The open device socket, so the watchdog can close the session before it kills the process.
_SOCK = None


def close_session(s):
    """Stop the screen stream and the RPC session before closing the port.
    Without this the device keeps the stream (and buffers) alive -> leaks RAM and a
    later preload fails with 'Not enough memory'."""
    try:
        send(s, b"\xAA\x01\x00")   # Main.gui_stop_screen_stream_request (field 21)
        time.sleep(0.15)
        send(s, b"\x9A\x01\x00")   # Main.stop_session (field 19)
        time.sleep(0.15)
    except Exception:
        pass


def send_app(s, name, args=""):
    """Main.app_start_request (field 16) { name=1, args=2 } -> launch an app by id."""
    sub = b"\x0a" + varint(len(name)) + name.encode()
    if args:
        sub += b"\x12" + varint(len(args)) + args.encode()
    send(s, b"\x82\x01" + varint(len(sub)) + sub)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    # ponytail: global watchdog. A busy FAP (e.g. channel-hop looping) can stop
    # draining USB CDC and block serial open/write; without this the call hangs
    # forever and leaves the RPC session orphaned, bricking the CLI until reboot.
    if hasattr(signal, "SIGALRM"):
        def _bail(_sig, _frm):
            print("timeout"); sys.stdout.flush()
            # Close the RPC session BEFORE dying. os._exit() skips the normal close path, and a
            # session left open keeps the screen stream (and its buffers) alive on the device - the
            # exact leak the runbook warns about ("leaks RAM and a later preload fails with 'Not
            # enough memory'"). Every watchdog timeout used to leak one, and this project's
            # intermittent out-of-memory crashes began during a day of hundreds of these calls.
            try:
                if _SOCK is not None:
                    close_session(_SOCK)
            except Exception:
                pass
            import os; os._exit(2)
        signal.signal(signal.SIGALRM, _bail)
        signal.alarm(20)
    settle = 0.25
    if "--settle" in args:
        settle = float(args[args.index("--settle") + 1])
    shot = None
    if "--shot" in args:
        shot = args[args.index("--shot") + 1]

    global _SOCK
    s = connect()
    _SOCK = s
    cmd = args[0]
    try:
        if cmd == "shot":
            send(s, b"\xA2\x01\x00")
            time.sleep(0.5)
            d = grab(s)
            if d:
                png(args[1], d)
                print("saved", args[1])
            else:
                print("no frame")
        elif cmd == "app":
            name = args[1]
            send_app(s, name, args[2] if len(args) > 2 and not args[2].startswith("--") else "")
            print("started app", name)
            time.sleep(2.0)
            send(s, b"\xA2\x01\x00")
            time.sleep(0.4)
            d = grab(s)
            if d:
                png(shot or "/tmp/flip.png", d)
                print("saved", shot or "/tmp/flip.png")
            else:
                print("no frame")
        elif cmd == "key":
            send_key(s, args[1], args[2] if len(args) > 2 else "SHORT")
            print("key", args[1])
        elif cmd == "press":
            send_press(s, args[1])
            print("press", args[1])
        elif cmd == "drive":
            rest = args[1:]
            seq = []
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--shot", "--settle"):
                    i += 2
                    continue
                seq.append(a)
                i += 1
            for it in seq:
                parts = it.split(":")
                k = parts[0]
                if ":" in it and parts[1] in TYPES:
                    send_key(s, k, parts[1])   # explicit type override
                else:
                    send_press(s, k)
                time.sleep(settle)
            send(s, b"\xA2\x01\x00")
            time.sleep(0.4)
            d = grab(s)
            if d:
                png(shot or "/tmp/flip.png", d)
                print("saved", shot or "/tmp/flip.png")
            else:
                print("no frame")
        else:
            print(__doc__)
            return 1
    finally:
        close_session(s)
        s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
