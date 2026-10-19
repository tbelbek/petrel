#!/usr/bin/env bash
# Build Petrel firmware for Ai-Thinker BW16 (RTL8720DN) in a linux/amd64 container,
# so the x86_64 AmebaD toolchain runs natively (no Rosetta). Flash from the Mac afterwards.
set -euo pipefail
SKETCH_DIR="${1:?sketch dir}"   # .../Petrel/RTL8720dn-firmware
OUT_DIR="${2:?out dir}"
A15="${3:?arduino15 cache dir}"
COMMON_DIR="$(cd "$(dirname "$SKETCH_DIR")" && pwd)/common"   # repo common/: shared headers
IDX="https://github.com/Ameba-AIoT/ameba-arduino-d/raw/dev/Arduino_package/package_realtek_amebad_early_index.json"
FQBN="realtek:AmebaD:Ai-Thinker_BW16"
# Pin the core to petrel's era (last real commit 2025-04); 3.2.0 (2026) broke the core headers.
CORE_VER="${CORE_VER:-3.1.7-build20240216}"
mkdir -p "$OUT_DIR" "$A15"

PATCH_DIR="$(cd "$(dirname "$0")" && pwd)"   # holds patch_wificlient.py
docker run --rm --platform linux/amd64 \
  -v "$SKETCH_DIR":/sketch:ro \
  -v "$COMMON_DIR":/common:ro \
  -v "$OUT_DIR":/out \
  -v "$A15":/root/.arduino15 \
  -v "$PATCH_DIR":/patch:ro \
  -e IDX="$IDX" -e FQBN="$FQBN" -e CORE_VER="$CORE_VER" \
  debian:bookworm-slim bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl python3 python3-pip git ca-certificates xxd >/dev/null
    ln -sf /usr/bin/python3 /usr/local/bin/python
    if ! command -v arduino-cli >/dev/null 2>&1; then
      curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh \
        | BINDIR=/usr/local/bin sh >/dev/null
    fi
    arduino-cli version
    arduino-cli config init --overwrite >/dev/null
    # A transient GitHub index fetch failure must not abort the build when the core is already
    # cached in the mounted arduino15 dir; if the core is genuinely missing, the install below
    # fails with a clear error anyway.
    arduino-cli core update-index --additional-urls "$IDX" || echo "index update failed; using cached"
    # Pin exactly CORE_VER: remove any other installed AmebaD, install the pinned one.
    if ! arduino-cli core list 2>/dev/null | grep -qi "realtek:AmebaD[[:space:]].*$CORE_VER"; then
      arduino-cli core uninstall realtek:AmebaD 2>/dev/null || true
      arduino-cli core install "realtek:AmebaD@$CORE_VER" --additional-urls "$IDX"
    else
      echo "AmebaD core $CORE_VER already installed (cached)"
    fi
    # patch core WiFiClient to expose remoteIP() (per-client captive 204 needs peer IP)
    CORE_WIFI="/root/.arduino15/packages/realtek/hardware/AmebaD/$CORE_VER/libraries/WiFi/src"
    python3 /patch/patch_wificlient.py "$CORE_WIFI"
    # patch core BLEClient to expose the discovered service/characteristic UUIDs (host UI)
    CORE_BLE="/root/.arduino15/packages/realtek/hardware/AmebaD/$CORE_VER/libraries/BLE/src"
    python3 /patch/patch_bleclient.py "$CORE_BLE"
    # D.4/2: split wifi_on/wifi_off into begin/poll + dedicated open test-AP entry points
    # (cooperative AP lifecycle; legacy synchronous callers keep their behaviour via wrappers)
    CORE_ROOT="/root/.arduino15/packages/realtek/hardware/AmebaD/$CORE_VER"
    python3 /patch/patch_apsplit.py "$CORE_ROOT"
    # sketch folder name must match the .ino basename; /sketch is mounted ro so copy it
    INO=$(basename /sketch/*.ino .ino)
    cp -r /sketch "/tmp/$INO"
    # M0.2: Arduino only includes sketch-local headers, so drop the shared transport header
    # (canonical in repo common/) into the sketch copy. Single source, copied in at build.
    cp /common/petrel_proto.h /common/wids.h "/tmp/$INO/"
    echo "=== compiling $INO ==="
    arduino-cli compile --fqbn "$FQBN" --output-dir /out --build-path /out/build -v "/tmp/$INO" 2>&1 \
      | grep -iE "postbuild|img2|image2|km0_km4|error|undefined|reference to|overflow|region|ld:|warning:|Sketch uses|\.bin" | tail -30
    echo "=== images in /out (save_file target) ==="; find /out -maxdepth 2 -iname "*.bin" -exec ls -la {} \;
  '
