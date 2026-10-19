#!/usr/bin/env python3
"""board_cmd - send one command to the BW16/RTL8720DN over CH340 and print the reply.

DANGER: opening the CH340 asserts DTR/RTS by default, and RTS->BOOT drops the BW16 into
download mode. We drop both the instant the port is open (the board may blink/reset once).
The firmware's loop() also reads USB Serial, so this doubles as an out-of-band control
channel (e.g. "STOP" to tear the AP down when the FAP is hung).

Usage:  python3 board_cmd.py "STOP"     [--wait 2.0] [--read 3000]
        python3 board_cmd.py --seq "CHANNEL 11" "APSTART myAP"   # ONE port session

TRAP 1 (cost a whole false diagnosis): the flag *values* used to leak into the command.
The old parser only dropped args that started with "--", so
    board_cmd.py "APSTART PETRELAP" --wait 14 --read 8000
sent "APSTART PETRELAP 14 8000" and the firmware created an AP with the SSID
"PETRELAP 14 8000" - the AP was beaconing all along, we just scanned the wrong name and
concluded "the AP never comes up". Consume each flag's value explicitly (below).

TRAP 2 (cost another one): opening/closing the CH340 RESETS the BW16, so every setting the
firmware keeps in a global is lost between two calls of this script. "CHANNEL 11" followed by
a separate "APSTART myAP" leaves ap_channel empty, createAP() falls back to its default 6, and
the channel looks ignored - a firmware bug that is not one. State-setting commands must share
ONE port session with the command that consumes them: use --seq.

TRAP 3: the firmware drains BOTH UARTs into one line buffer and, once the buffer ends in '\n',
runs the giant if/else chain and then clears the whole buffer. Two commands that land in the
same loop() pass are therefore processed as the FIRST one only - the second is silently
dropped. --seq writes each command and waits REFRESH_GAP_S between them so that each arrives in
its own pass.
"""
import sys
import time

import serial

PORT = "/dev/cu.usbserial-20220"

# Gap between the commands of a --seq run: long enough that the firmware's loop() picks each one
# up in its own pass (see TRAP 3), short enough to keep a multi-command setup quick.
REFRESH_GAP_S = 0.35

# --gap overrides the per-command gap. Needed when a command needs time to take effect inside the
# SAME session - e.g. APSTART, which must be up before a following STOP/SCAN can be meaningful.
# The port cannot be closed in between: closing it resets the board (see TRAP 2).

# Flags whose *next* argument is their value and must never reach the board.
VALUE_FLAGS = {"--wait": float, "--read": int, "--gap": float}


def parse_args(argv):
    """Split argv into (commands, wait, read), consuming flag values explicitly.

    Without --seq the arguments form ONE command (joined with spaces). With --seq each argument
    is a separate command, sent as its own line inside the single port session, so any state an
    earlier line sets is still there for the later ones (TRAP 2), each in its own loop() pass
    (TRAP 3).
    """
    cmd_parts = []
    wait = 2.0
    read = 4000
    gap = REFRESH_GAP_S
    seq = False
    i = 0
    while i < len(argv):
        a = argv[i]
        conv = VALUE_FLAGS.get(a)
        if conv is not None:
            if i + 1 >= len(argv):
                raise SystemExit(f"board_cmd: {a} needs a value")
            v = conv(argv[i + 1])
            if a == "--wait":
                wait = v
            elif a == "--gap":
                gap = v
            else:
                read = v
            i += 2
            continue
        if a == "--seq":
            seq = True
            i += 1
            continue
        cmd_parts.append(a)
        i += 1
    return (cmd_parts if seq else [" ".join(cmd_parts)]), wait, read, gap


def main():
    cmds, wait, read, gap = parse_args(sys.argv[1:])

    s = serial.Serial(PORT, 115200, timeout=0.3)
    try:
        s.dtr = False
        s.rts = False
    except Exception:
        pass
    time.sleep(0.3)
    s.reset_input_buffer()
    for n, cmd in enumerate(cmds):
        if n:
            # One command per loop() pass: two lines delivered together are collapsed into the
            # first one by the firmware's chain (TRAP 3) and the second is lost.
            time.sleep(gap)
        s.write((cmd + "\n").encode())
    time.sleep(wait)
    sys.stdout.write(s.read(read).decode("utf-8", "replace"))
    s.close()


if __name__ == "__main__":
    main()
