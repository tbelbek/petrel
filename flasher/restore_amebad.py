#!/usr/bin/env python3
"""
restore_amebad.py — Re-flash a BW16 (RTL8720DN) from a full 2 MB backup made by
dump_amebad.py (read from base 0x08000000).

It splits the monolithic image at the three AmebaD flash regions and hands them
to upload_amebad.flash_image, reusing the proven erase/write/verify/reset path.

    python3 restore_amebad.py 5ghost-stock-fw-2026-10-14.bin /dev/cu.usbserial-20220

Regions (FLASH_MAP in upload_amebad.py):
    km0_boot_all.bin    0x08000000  (backup 0x0000..0x4000)
    km4_boot_all.bin    0x08004000  (backup 0x4000..0x6000)
    km0_km4_image2.bin  0x08006000  (backup 0x6000..content-end, 4K-aligned)
"""
import os, sys, tempfile, shutil
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import upload_amebad as U

SPLITS = [("km0_boot_all.bin", 0x0000, 0x4000),
          ("km4_boot_all.bin", 0x4000, 0x6000),
          ("km0_km4_image2.bin", 0x6000, None)]  # None = to content end


def main():
    if len(sys.argv) < 3:
        print("usage: restore_amebad.py <backup.bin> <port> [floader.bin]")
        return 2
    backup, port = sys.argv[1], sys.argv[2]
    floader = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
        os.path.expanduser("~"), "Repos/flipper/ambd_flash_tool/imgtool_flashloader_amebad.bin")

    d = open(backup, "rb").read()
    if d[:4] != bytes([0x99, 0x99, 0x96, 0x96]):
        print("!! %s does not start with the AmebaD boot marker 99999696 — wrong file?" % backup)
        return 1
    # content end = last non-0xFF byte, rounded up to 4 KB
    end = len(d)
    while end > 0 and d[end - 1] == 0xFF:
        end -= 1
    end = (end + 0xFFF) & ~0xFFF

    td = tempfile.mkdtemp(prefix="ambd_restore_")
    try:
        shutil.copy(floader, os.path.join(td, "imgtool_flashloader_amebad.bin"))
        for name, a, b in SPLITS:
            b = end if b is None else b
            open(os.path.join(td, name), "wb").write(d[a:b])
            print("  %-20s <- 0x%06X..0x%06X (%d B)" % (name, a, b, b - a))
        print("flashing %s -> %s" % (backup, port))
        ok = U.flash_image(port, td, auto_mode=True, verbose=1)
        return 0 if ok else 1
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
