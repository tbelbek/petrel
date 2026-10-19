#!/usr/bin/env python3
"""flip_suite - run the FULL Petrel UI/action suite over USB RPC.

Workflow: run the WHOLE suite, screenshot EVERY step, log details, NOTE bugs
(do NOT fix mid-run). Then fix the bugs in bulk and re-run until clean.

Design notes
  * App is launched via the plain CLI (`loader open <fap>`), NOT the file browser (bug #8).
  * One action group per step; every step writes a screenshot + a run.log line.
  * RX/observation steps first; TX steps (deauth/beacon/portal) later; the KNOWN HANG
    ("Channel hop on/off") is LAST, after which we reboot + relaunch.
  * Each flipctl call is a separate process with a 20 s in-process watchdog, so a stuck FAP
    can't hang the suite.

Usage:  python3 flip_suite.py [phase]     phase: wifi | tools | ble | all (default all)
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/suite"
os.makedirs(T, exist_ok=True)
RUNLOG = os.path.join(T, "run.log")
FAP = "/ext/apps/GPIO/petrelrtl.fap"
PY = sys.executable

_n = [0]


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(RUNLOG, "a") as f:
        f.write(line + "\n")


def cli(cmd, wait=1.5):
    try:
        r = subprocess.run([PY, os.path.join(HERE, "flip_cli.py"), cmd],
                           capture_output=True, text=True, timeout=25)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "<<cli timeout>>"


def shot(name, tmo=25):
    p = os.path.join(T, name + ".png")
    try:
        r = subprocess.run([PY, os.path.join(HERE, "flipctl.py"), "shot", p],
                           capture_output=True, text=True, timeout=tmo)
        ok = ("saved" in r.stdout) and os.path.exists(p)
    except subprocess.TimeoutExpired:
        ok = False
    log(f"    shot {name}: {'ok' if ok else 'NOFRAME/HANG'}")
    return ok


def drive(keys, shot_name=None, settle=0.35, wait=0.0):
    args = [PY, os.path.join(HERE, "flipctl.py"), "drive", *keys, "--settle", str(settle)]
    if shot_name:
        args += ["--shot", os.path.join(T, shot_name + ".png")]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=45)
        ok = "saved" in r.stdout
    except subprocess.TimeoutExpired:
        ok = False
    log(f"    drive {' '.join(keys)} -> {shot_name or ''}: {'ok' if ok else 'NOFRAME/HANG'}")
    if wait:
        time.sleep(wait)
    return ok


def step(desc):
    _n[0] += 1
    log(f"STEP {_n[0]:02d}  {desc}")
    return _n[0]


def reboot_relaunch():
    log("  [recovery] reboot + loader open")
    try:
        subprocess.run([PY, os.path.join(HERE, "flip_reboot.py")],
                       capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(5)
    out = cli(f"loader open {FAP}", wait=3.5)
    log("    loader open -> " + " / ".join(out.strip().splitlines()[-1:]))
    time.sleep(2)


# ----------------------------------------------------------------------------- phases

def phase_wifi():
    step("app running? (loader info)")
    log("    " + cli("loader info").strip().splitlines()[-1])

    # --- main menu nav ---
    step("main menu: current")
    shot("w00-main")
    step("main nav RIGHT (-> BLE)")
    drive(["RIGHT"], "w01-right")
    step("main nav DOWN (-> Exit)")
    drive(["DOWN"], "w02-down")
    step("main nav LEFT (-> Help)")
    drive(["LEFT"], "w03-left")
    step("main nav UP (-> Wi-Fi)")
    drive(["UP"], "w04-up")

    # --- Wi-Fi hub ---
    step("open Wi-Fi hub")
    drive(["OK"], "w05-hub")
    step("Scan Wifi (busy + result)")
    drive(["OK"], None, wait=1.5)
    shot("w06-scan-busy")
    time.sleep(14)
    shot("w07-scan-after")
    step("BACK to hub")
    drive(["BACK"], "w08-hub")

    step("List Wifi")
    drive(["DOWN", "OK"], "w09-list")
    step("select AP #1 -> info screen")
    drive(["OK"], "w10-info-1")
    step("info: DOWN through list (AP #2, #3)")
    drive(["BACK", "DOWN", "OK"], "w11-info-2")
    drive(["BACK", "DOWN", "DOWN", "OK"], "w12-info-3")

    step("info button LEFT -> attack config")
    drive(["LEFT"], "w13-attackcfg")
    step("config: Deauth Reason cycle (RIGHT)")
    drive(["RIGHT"], "w14-reason")
    step("config: down to Portal Type, cycle (RIGHT)")
    drive(["DOWN", "RIGHT"], "w15-portal")
    step("config: down to Mac Type, cycle (RIGHT)")
    drive(["DOWN", "RIGHT"], "w16-mactype")

    step("config -> Tools submenu")
    drive(["DOWN", "OK"], "w17-tools")

    step("Tools: BACK out to config, BACK to info, BACK to list")
    drive(["BACK", "BACK", "BACK"], "w18-list")

    step("info screen: right button (Evil)")
    drive(["OK", "RIGHT"], "w19-evil")

    step("back to hub")
    drive(["BACK", "BACK"], "w20-hub")

    step("Channel Map")
    drive(["DOWN", "DOWN", "OK"], "w21-chanmap")
    drive(["RIGHT"], "w22-chanmap-pan")
    step("Channel Map -> back to hub")
    drive(["BACK"], "w23-hub")

    step("Create AP (TX/state change)")
    drive(["DOWN", "DOWN", "DOWN", "OK"], None, wait=1.5)
    shot("w24-createap-busy")
    time.sleep(4)
    shot("w25-createap-after")
    step("back to hub")
    drive(["BACK"], "w26-hub")

    step("Send Beacon (TX)")
    drive(["DOWN", "DOWN", "DOWN", "DOWN", "OK"], None, wait=1.5)
    shot("w27-beacon-busy")
    time.sleep(4)
    shot("w28-beacon-after")
    step("back to hub")
    drive(["BACK"], "w29-hub")

    step("Load Portal (list SD portals)")
    drive(["DOWN", "DOWN", "DOWN", "DOWN", "DOWN", "OK"], "w30-portal-list")
    step("portal list -> OK on first")
    drive(["OK"], "w31-portal-open")
    step("back out")
    drive(["BACK", "BACK", "BACK"], "w32-hub")


def phase_tools():
    step("navigate: hub -> List -> AP -> info -> Edit -> config -> Tools")
    drive(["OK", "DOWN", "OK", "OK", "LEFT", "DOWN", "DOWN", "DOWN", "OK"], "t00-tools")

    step("T01 Capture HS (passive)")
    drive(["OK"], None, wait=1.5)
    shot("t01-caphs-busy")
    time.sleep(12)
    shot("t01-caphs-after")
    drive(["BACK"], "t01-back")

    step("T02 Grab HS (deauth)  [TX]")
    drive(["DOWN", "OK"], None, wait=1.5)
    shot("t02-grabhs-busy")
    time.sleep(14)
    shot("t02-grabhs-after")
    drive(["BACK"], "t02-back")

    step("T03 PMKID (passive)")
    drive(["DOWN", "DOWN", "OK"], None, wait=1.5)
    shot("t03-pmkid-busy")
    time.sleep(12)
    shot("t03-pmkid-after")
    drive(["BACK"], "t03-back")

    step("T04 PMKID grab (deauth)  [TX]")
    drive(["DOWN", "DOWN", "DOWN", "OK"], None, wait=1.5)
    shot("t04-pmkidgrab-busy")
    time.sleep(14)
    shot("t04-pmkidgrab-after")
    drive(["BACK"], "t04-back")

    step("T05 PMKID clientless (raw)  [TX]")
    drive(["DOWN", "DOWN", "DOWN", "DOWN", "OK"], None, wait=1.5)
    shot("t05-clientless-busy")
    time.sleep(12)
    shot("t05-clientless-after")
    drive(["BACK"], "t05-back")

    step("T06 Capture: STOP")
    drive(["DOWN"] * 5 + ["OK"], "t06-capstop")
    drive(["BACK"], "t06-back")

    step("T07 Guided audit (this AP)  [TX]")
    drive(["DOWN"] * 6 + ["OK"], None, wait=1.5)
    shot("t07-audit-busy")
    time.sleep(16)
    shot("t07-audit-after")
    drive(["BACK"], "t07-back")

    step("T08 PMF/WPA3 scan (passive)")
    drive(["DOWN"] * 7 + ["OK"], None, wait=1.5)
    shot("t08-pmf-busy")
    time.sleep(12)
    shot("t08-pmf-after")
    drive(["BACK"], "t08-back")

    step("T09 STASCAN (stations)")
    drive(["DOWN"] * 8 + ["OK"], None, wait=1.5)
    shot("t09-stascan-busy")
    time.sleep(12)
    shot("t09-stascan-after")
    drive(["BACK"], "t09-back")

    step("T10 Deauth list: +this AP")
    drive(["DOWN"] * 9 + ["OK"], "t10-deauthadd")
    drive(["BACK"], "t10-back")

    step("T11 Deauth list: RUN  [TX]")
    drive(["DOWN"] * 10 + ["OK"], None, wait=2.0)
    shot("t11-deauthrun")
    time.sleep(5)
    drive(["BACK"], "t11-back")

    step("T12 Deauth list: STOP")
    drive(["DOWN"] * 11 + ["OK"], "t12-deauthstop")
    drive(["BACK"], "t12-back")

    step("T13 Stop/clear (last item)")
    drive(["DOWN"] * 13 + ["OK"], "t13-stopclear")
    drive(["BACK"], "t13-back")

    step("T14 Channel hop on/off  [KNOWN HANG]")
    drive(["DOWN"] * 12 + ["OK"], None, wait=2.0)
    shot("t14-hop")           # likely NOFRAME/HANG
    log("    (hang expected -> recovery)")
    reboot_relaunch()


def phase_ble():
    step("main -> BLE hub")
    drive(["RIGHT", "OK"], "b00-blehub")
    for i, name in enumerate([
        "BLE Scan", "iBeacon 1", "iBeacon 2", "BadBLE 1", "BadBLE 2",
        "BLE Adv 1", "BLE Adv 2", "Saved adverts",
    ]):
        step(f"BLE item {i}: {name}")
        drive(["DOWN"] * i + ["OK"], None, wait=1.5)
        shot(f"b{i:02d}-{name.replace(' ', '_').lower()}")
        time.sleep(6)
        shot(f"b{i:02d}-after")
        drive(["BACK", "BACK"], f"b{i:02d}-back")


def phase_help_exit():
    step("Help screen")
    drive(["BACK", "DOWN", "DOWN", "OK"], "x00-help")   # from BLE hub: BACK, then Help cell
    step("Exit app")
    drive(["BACK", "DOWN", "OK"], "x01-exit")


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "all"
    log(f"================ SUITE phase={phase} ================")
    if phase in ("all", "wifi"):
        reboot_relaunch()          # known start state: main card menu
    steps = {
        "wifi": phase_wifi,
        "tools": phase_tools,
        "ble": phase_ble,
    }
    if phase == "all":
        for p in ("wifi", "tools", "ble"):
            steps[p]()
    else:
        steps[phase]()
    log("================ SUITE done ================")


if __name__ == "__main__":
    main()
