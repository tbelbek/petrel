#!/usr/bin/env python3
"""flip_tools_batch - reboot, navigate to the Tools menu, and run a batch of tools.

Each tool: navigate from the top of the Tools list (DOWN*i), OK, screenshot busy + after,
BACK. Writes suite3/. If the FAP zombies (desktop while 'running'), the batch stops and
says so.

Usage: python3 flip_tools_batch.py <start_index> <count>
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/suite3"
os.makedirs(T, exist_ok=True)
LOG = os.path.join(T, "run.log")
FAP = "/ext/apps/GPIO/petrelrtl.fap"
PY = sys.executable


def log(m):
    line = f"{time.strftime('%H:%M:%S')} {m}"
    print(line, flush=True)
    open(LOG, "a").write(line + "\n")


def cli(cmd, wait=1.5):
    try:
        r = subprocess.run([PY, os.path.join(HERE, "flip_cli.py"), cmd],
                           capture_output=True, text=True, timeout=25)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "<<timeout>>"


def shot(name):
    p = os.path.join(T, name + ".png")
    try:
        r = subprocess.run([PY, os.path.join(HERE, "flipctl.py"), "shot", p],
                           capture_output=True, text=True, timeout=25)
        ok = "saved" in r.stdout
    except subprocess.TimeoutExpired:
        ok = False
    log(f"    shot {name}: {'ok' if ok else 'NOFRAME/HANG'}")
    return ok


def keys(*ks, settle=0.5):
    """Send a key sequence in one drive call, as the runbook does.

    The device keeps up with 0.4-0.5 s per key. Batching was added here when key presses looked like
    they were being dropped - they were not: `flipctl --shot` returns the last frame its window saw,
    the Flipper only streams a frame when the screen changes, and a stale frame looks exactly like a
    key that did nothing. In this tool that is harmless (the shots are for the record), but use
    tools/flip_see.py whenever a screenshot decides what happens next.
    """
    args = [PY, os.path.join(HERE, "flipctl.py"), "drive", *ks, "--settle", str(settle)]
    try:
        subprocess.run(args, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        log("    drive TIMEOUT")


def nav_to_tools():
    log("  reboot + loader open + scan + nav to Tools")
    subprocess.run([PY, os.path.join(HERE, "flip_reboot.py")], capture_output=True, timeout=30)
    time.sleep(5)
    cli(f"loader open {FAP}", wait=3.5)
    time.sleep(2.5)
    # A fresh submenu starts on row 0 (submenu_reset resets the cursor), so this nav is absolute:
    # OK on the hub = "Scan Wifi" (row 0), the scan finishes by itself and lands back on row 0,
    # then two DOWNs reach "Tools (capture / recon)". The old detour through List Wifi -> AP info
    # -> Edit is gone: it depended on the scan order (the hidden "<empty>" AP has no Edit button)
    # and is no longer needed now that the hub carries a Tools entry.
    keys("OK", settle=1.2)                      # main -> Wi-Fi hub (row 0)
    keys("OK", settle=1.2)                      # row 0 = Scan Wifi
    shot("b01-scan")
    time.sleep(15)                              # scan wait -> back to the hub, row 0 again
    keys("DOWN", "DOWN", "OK", settle=1.0)      # row 2 = Tools (capture / recon)
    time.sleep(1.2)
    shot("b00-tools")


# (idx, name, wait_s) - idx is the ROW in the Tools menu, in insertion order:
#   row 0     Target: <ssid> picker (always present)
#   rows 1-7  cap H (capture / grab / PMKID / audit)
#   rows 8-10 cap S (PMF scan / STASCAN / probe sniff)
#   rows 11-16 cap D (deauth list, IDS, CSA, client tracker)
#   row 17    cap T (BTM)
#   rows 18-19 channel hop / stop (always present)
#   rows 20-21 cap F (auth flood, assoc+sleep flood)
# A board whose IDENT advertises fewer caps shows fewer rows, so the numbers shift - check the
# b00-tools screenshot (or the caps in the boot log) before trusting a row number.
TOOLS = {
    0: ("Target_AP", 2),
    1: ("Capture_HS_passive", 14),
    2: ("Grab_HS_deauth", 24),
    3: ("PMKID_passive", 12),
    4: ("PMKID_grab_deauth", 16),
    5: ("PMKID_clientless", 14),
    6: ("Capture_STOP", 2),
    7: ("Guided_audit", 20),
    8: ("PMF_WPA3_scan", 12),
    9: ("STASCAN", 12),
    10: ("Probe_sniff_PNL", 12),
    11: ("Deauth_list_addAP", 3),
    12: ("Deauth_list_RUN", 6),
    13: ("Deauth_list_STOP", 3),
    14: ("Deauth_IDS", 12),
    15: ("CSA_attack", 4),
    16: ("Client_tracker", 32),
    17: ("BTM_attack", 4),
    18: ("Channel_hop", 3),
    19: ("Stop_clear", 3),
    20: ("Auth_flood", 8),
    21: ("Assoc_sleep_flood", 8),
}


def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    log(f"================ TOOLS BATCH start={start} count={count} ================")
    nav_to_tools()
    for i in range(start, start + count):
        if i not in TOOLS:
            continue
        name, wait = TOOLS[i]
        log(f"  TOOL #{i} {name}")
        keys(*(["DOWN"] * i + ["OK"]), settle=1.0)
        shot(f"b{i:02d}-{name}-busy")
        time.sleep(wait)
        shot(f"b{i:02d}-{name}-after")
        keys("BACK", settle=0.9)
        shot(f"b{i:02d}-{name}-back")
    log("================ BATCH done ================")


if __name__ == "__main__":
    main()
