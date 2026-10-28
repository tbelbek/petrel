#!/usr/bin/env python3
"""flip_shot - FAP'in SD'ye yazdigi kareyi PNG'ye cevir (RPC YOK).

Neden: `flipctl.py shot` bir RPC oturumu acar ve o oturum Flipper heap'inden ~20 KB alir
(2026-10-28 kosusunda olculdu). FAP derin ekranlarda ~19 KB bos biraktigi icin ekran goruntusu
OOM cokmesine yol aciyordu. Bu arac RPC kullanmaz: FAP kendi framebuffer'ini
/ext/petrel/shot.hex dosyasina yazar (64 hex karakterlik satirlar), biz CLI'den okuyup PNG yapariz.

Kullanim:
  flip_shot.py <cikti.png>
"""
import re
import struct
import sys
import zlib

import serial

PORT = "/dev/cu.usbmodemflip_Uy0th11"
RAW_PATH = "/ext/petrel/shot.hex"
W, H = 128, 64
BYTES = W * H // 8  # 1024


def cli(cmd, wait=1.2):
    p = serial.Serial(PORT, 115200, timeout=0.6)
    try:
        p.reset_input_buffer()
        p.write(b"\r")
        p.read(4096)
        p.write((cmd + "\r").encode())
        # 2 KB hex + prompt: 16 KB okuma sinirinin cok altinda
        import time

        time.sleep(wait)
        return p.read(16384).decode("utf-8", "replace")
    finally:
        p.close()


def read_frame(timeout_note=""):
    out = cli("storage read " + RAW_PATH)
    rows = [ln.strip() for ln in out.splitlines()]
    hexrows = [ln for ln in rows if len(ln) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", ln)]
    if not hexrows:
        # bazi firmware'ler bosluk/CR birakir; daha gevsek dene
        hexrows = [ln for ln in rows if re.fullmatch(r"[0-9a-fA-F]{64}", ln.strip())]
    if not hexrows:
        raise SystemExit(
            "shot.hex okunamadi%s\n--- CLI ciktisi ---\n%s" % (timeout_note, out[:800])
        )
    blob = bytes.fromhex("".join(hexrows))
    if len(blob) < BYTES:
        raise SystemExit("kisa kare: %d bayt (beklenen %d)" % (len(blob), BYTES))
    return blob[:BYTES]


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


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    png(sys.argv[1], read_frame())
    print("saved", sys.argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
