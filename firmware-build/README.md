# Petrel BW16 firmware — build & flash

Builds the RTL8720DN firmware in a `linux/amd64` Docker container (native x86_64
AmebaD toolchain, no Rosetta). Flash tools live in `../../amebad-flasher/`.

## Build
    bash build_petrel.sh <sketch_dir> <out_dir> <arduino15_cache_dir>
    # sketch_dir = ../RTL8720dn-firmware ; output: <out_dir>/build/km0_km4_image2.bin

- Core pinned to AmebaD **3.1.7-build20240216** (3.2.0 breaks the core headers).
- `patch_wificlient.py` adds `WiFiClient::remoteIP()` (lwip getpeername via a C helper
  in ard_socket.c) — needed for per-client captive 204. Run against the installed core;
  idempotent. Re-applied on every build.
- `patch_dhcps.py` — reference patch to add DHCP option 114 to the SDK dhcps.c. NOT used:
  dhcps is prebuilt in lib_arduino.a, so petrel runs its own DHCP server (dhcp_captive.cpp).
- `test_dhcp_build.c` — host self-test for the option-114 DHCP packet builder:
    cc -I../RTL8720dn-firmware test_dhcp_build.c -o t && ./t

## Flash (from amebad-flasher/, pure-Python, native arm64)
    python3 flash_petrel.py [image2.bin] [/dev/cu.usbserial-XXXX]
- Writes ONLY km0_km4_image2.bin to 0x08006000 (boot + 0x3000 RF calibration untouched).
- Use **115200** baud (default); the CH340 stalls the flashloader upload at 1.5M.

## Drive without a Flipper (testing)
The firmware reads the same UART command protocol on USB (Serial/CH340) as on the
Flipper (Serial1). Example (channel first, else apbegin fails RTKIOCSIWFREQ):
    printf 'CHANNEL 6\nAPSTART TEST\n' > /dev/cu.usbserial-XXXX
