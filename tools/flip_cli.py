#!/usr/bin/env python3
"""flip_cli - send a raw CLI command to the Flipper over USB and print the reply.

The Flipper's USB CDC port can only be held by one process at a time: this opens it
in plain CLI text mode (NOT start_rpc_session), so it can coexist with `flipctl` only
if no RPC session is open.

Usage:
  flip_cli.py "loader info"
  flip_cli.py "loader open /ext/apps/GPIO/petrelrtl.fap"
  flip_cli.py "storage list /ext/apps/GPIO"
"""
import sys
import time

import serial

PORT = "/dev/cu.usbmodemflip_Uy0th11"


def cli(cmd, wait=1.2, port=PORT):
    p = serial.Serial(port, 115200, timeout=0.6)
    try:
        time.sleep(0.4)
        p.reset_input_buffer()
        p.write(b"\r")
        time.sleep(0.3)
        p.read(4096)
        p.write((cmd + "\r").encode())
        time.sleep(wait)
        return p.read(16384).decode("utf-8", "replace")
    finally:
        p.close()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = " ".join(sys.argv[1:])
    sys.stdout.write(cli(cmd))
    return 0


if __name__ == "__main__":
    sys.exit(main())
