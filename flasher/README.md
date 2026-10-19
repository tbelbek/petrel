# Flashing Petrel onto a BW16 / RTL8720DN

Flashes **only** the application image (`km0_km4_image2.bin`) over the CH340 USB-serial bridge.
Boot loader + calibration data are left untouched, so the board stays recoverable.

## Requirements
- A BW16 / RTL8720DN board on USB (CH340). Note the serial port (e.g. `/dev/cu.usbserial-XXXX`
  on macOS, `/dev/ttyUSB0` on Linux, `COMx` on Windows).
- Python 3 with `pyserial` (`pip install pyserial`).
- The AmebaD flashloader `imgtool_flashloader_amebad.bin` (a Realtek binary, **not** redistributed
  here). Get it from Realtek's [`ambd_flash_tool`](https://github.com/ambiot/ambd_flash_tool) and
  drop it next to `flash_petrel.py`, or point `$PETREL_FLASHLOADER` at it.

## Steps
1. Build the firmware (see the top-level README), then copy the image next to the flasher:
   ```bash
   cp ../firmware-build/out/build/km0_km4_image2.bin ./petrel-km0_km4_image2.bin
   ```
2. Flash:
   ```bash
   python3 flash_petrel.py [image2.bin] [port]
   # defaults: ./petrel-km0_km4_image2.bin  and the first likely CH340 port
   # override the port with $PETREL_PORT if auto-detect picks the wrong one
   ```
3. The board auto-enters download mode (CH340 DTR/RTS). If it does not, **hold BOOT/BURN while
   re-plugging**, then re-run. On success you'll see `image2 flashed; board reset to boot`.

## Coming from another BW16 firmware?
The BW16 is the same module several closed firmwares ship on. Petrel only rewrites the application
image (`image2`), so you can flash it onto such a board and flash back later the same way.
`restore_amebad.py` is included for recovery if you ever need it.

> Flashing is reversible but at your own risk — see the project DISCLAIMER.
