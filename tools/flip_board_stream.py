#!/usr/bin/env python3
"""flip_board_stream - one CH340 session: send commands, then stream the board log to a file.

board_cmd.py prints only after its --wait; fwlog.py streams but cannot send. This does both in
ONE port session, so a test can start the AP and keep reading its output (APTEST:/STA:/EV:/DHCP:)
without a second open (opening the CH340 resets the board).

Usage:
  flip_board_stream.py <outfile> --cmd "PORTAL 1" --cmd "CHANNEL 10" --cmd "APSTART Free_Wifi"
  kill it with SIGTERM when done.
"""
import signal
import sys
import time

import serial

PORT = "/dev/cu.usbserial-20220"
GAP = 0.6


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    out = sys.argv[1]
    cmds = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--cmd" and i + 1 < len(sys.argv)]

    s = serial.Serial(PORT, 115200, timeout=0.2)
    try:
        s.dtr = False
        s.rts = False
    except Exception:
        pass
    time.sleep(0.4)
    s.reset_input_buffer()
    for c in cmds:
        s.write((c + "\n").encode())
        time.sleep(GAP)
    print("sent %d commands, streaming to %s" % (len(cmds), out), flush=True)

    stop = {"v": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(v=True))

    with open(out, "ab", buffering=0) as f:
        while not stop["v"]:
            c = s.read(4096)
            if c:
                ts = time.strftime("%H:%M:%S")
                for line in c.split(b"\n"):
                    if line:
                        f.write(("%s %s\n" % (ts, line.decode("utf-8", "replace"))).encode())
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
