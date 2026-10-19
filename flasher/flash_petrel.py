#!/usr/bin/env python3
"""
flash_petrel.py — Flash ONLY the application image (km0_km4_image2.bin) to the BW16
at flash offset 0x6000. Boot regions (0x0, 0x4000) and the system/RF-calibration
partition (0x3000) are NOT touched — lowest-risk way to swap the app firmware.

    python3 flash_petrel.py [image2.bin] [port]

Defaults, overridable without editing this file:
  image2      arg 1, else ./petrel-km0_km4_image2.bin (next to this script)
  port        arg 2, else $PETREL_PORT, else first CH340/usbserial port auto-detected
  flashloader $PETREL_FLASHLOADER, else ./imgtool_flashloader_amebad.bin (next to this script)
              The AmebaD flashloader is a Realtek binary (not redistributed here); grab
              imgtool_flashloader_amebad.bin from Realtek's ambd_flash_tool and drop it in
              this folder, or point $PETREL_FLASHLOADER at it.
"""
import os, sys, time, serial
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import upload_amebad as U

IMAGE2_ADDR = 0x08006000


def autodetect_port():
    """First CH340/usbserial-looking serial port, or None. Keeps the common case
    zero-config without pinning a developer-specific device node."""
    try:
        from serial.tools import list_ports
    except Exception:
        return None
    for p in list_ports.comports():
        hay = ("%s %s" % (p.device, p.description or "")).lower()
        if any(k in hay for k in ("usbserial", "ttyusb", "ch340", "wchusb", "slab")):
            return p.device
    return None


def probe_sync(ser, seconds=4.0):
    """Bounded wait for the download-mode SYNC (0x15) stream. Fails fast instead of
    letting program_spi_flash's wait_sync spin for minutes when the board never entered
    download mode."""
    ser.reset_input_buffer()
    t0 = time.time()
    old = ser.timeout
    ser.timeout = 0.2
    try:
        while time.time() - t0 < seconds:
            b = ser.read(1)
            if b and b[0] == U.SYNC:
                return True
    finally:
        ser.timeout = old
    return False


def main():
    img = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "petrel-km0_km4_image2.bin")
    port = (sys.argv[2] if len(sys.argv) > 2 else None) or os.environ.get("PETREL_PORT") or autodetect_port()
    if not port:
        print("!! no serial port given and none auto-detected — pass it as arg 2 or set "
              "$PETREL_PORT (e.g. /dev/cu.usbserial-XXXX or COM5)")
        return 2
    floader = os.environ.get("PETREL_FLASHLOADER") or os.path.join(HERE, "imgtool_flashloader_amebad.bin")
    if not os.path.isfile(floader):
        print("!! flashloader not found: %s\n   Place imgtool_flashloader_amebad.bin (from Realtek's "
              "ambd_flash_tool) next to this script, or set $PETREL_FLASHLOADER." % floader)
        return 2

    data = U.load_bin_file(img)
    if data[:8].hex() != "3831393538373131":  # "81958711" AmebaD image2 OTA signature
        print("!! %s is not an AmebaD image2 (bad OTA signature) — refusing to flash" % img)
        return 1
    print("image2: %d bytes -> 0x%08X  (boot + 0x3000 calibration untouched)" % (len(data), IMAGE2_ADDR))

    ser = serial.Serial(port=port, baudrate=115200, bytesize=serial.EIGHTBITS,
                        parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, timeout=2.0)
    try:
        # Enter download mode (DTR/RTS auto-reset), then confirm the SYNC stream before
        # committing to the flash sequence.
        for attempt in range(1, 4):
            U.enter_download_mode(ser)
            if probe_sync(ser, 4.0):
                print("download mode OK (sync stream seen, attempt %d)" % attempt)
                break
            print("no sync on attempt %d, retrying..." % attempt)
        else:
            print("!! board never entered download mode — it may need the BOOT/BURN "
                  "button held while re-plugging. Nothing was written.")
            return 2
        flashloader = U.load_bin_file(floader)
        fmap = [("km0_km4_image2.bin", IMAGE2_ADDR, data)]  # single region only
        # 115200: the CH340 stalls the flashloader upload at 1.5M; the dump proved 115200 solid.
        speed = int(os.environ.get("FLASH_SPEED", "115200"))
        ok = U.program_spi_flash(ser, speed, None, fmap, flashloader)
        if ok:
            U.reset_to_boot(ser)
            print("OK: petrel image2 flashed; board reset to boot")
        else:
            print("FAILED: flash did not complete")
        return 0 if ok else 1
    finally:
        ser.close()


if __name__ == "__main__":
    sys.exit(main())
