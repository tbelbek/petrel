#!/usr/bin/env python3
"""flip_untested - run ONLY the still-untested Petrel actions, one action + one shot each.

Already verified (SKIPPED here): app launch, main menu, Scan Wifi, List Wifi, AP-info render,
Edit -> attack config, Tools enumerate, Load Portal list, Channel Map render, Help.

App is relaunched via the CLI (`loader open`) before each phase -> guaranteed main-menu start.

Usage: python3 flip_untested.py [wifi|tools|ble|exit|all]
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = "/private/var/folders/d3/tc4kl8dj4_95r62sctcfk61h0000gn/T/opencode/suite2"
os.makedirs(T, exist_ok=True)
RUNLOG = os.path.join(T, "run.log")
FAP = "/ext/apps/GPIO/petrelrtl.fap"
PY = sys.executable


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


def launch():
    """Relaunch the FAP via CLI for a known start state (main card menu)."""
    out = cli(f"loader open {FAP}", wait=3.5)
    log("    launch -> " + " / ".join(out.strip().splitlines()[-1:]))
    time.sleep(2)


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


def drive(keys, name=None, settle=0.35, wait=0.0):
    args = [PY, os.path.join(HERE, "flipctl.py"), "drive", *keys, "--settle", str(settle)]
    if name:
        args += ["--shot", os.path.join(T, name + ".png")]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=45)
        ok = "saved" in r.stdout
    except subprocess.TimeoutExpired:
        ok = False
    log(f"    {' '.join(keys)} -> {name or ''}: {'ok' if ok else 'NOFRAME/HANG'}")
    if wait:
        time.sleep(wait)
    return ok


_n = [0]


def step(desc):
    _n[0] += 1
    log(f"STEP {_n[0]:02d}  {desc}")


# ------------------------------------------------------------------ phases

def setup_scan():
    """Precondition only (Scan is already verified): populate the AP list."""
    step("[setup] launch + Scan to populate AP list")
    launch()
    drive(["OK"], None, wait=0.8)              # Wi-Fi hub
    drive(["OK"], None, wait=1.5)              # Scan
    time.sleep(13)
    drive(["BACK"], None, wait=0.5)            # back to hub


def phase_wifi():
    step("Channel Map (render + Right to pan)")
    drive(["OK", "DOWN", "DOWN", "OK"], "e01-chanmap")
    drive(["RIGHT"], "e02-chanmap-pan")
    drive(["BACK"], None, wait=0.4)

    step("Create AP  [starts a softAP]")
    drive(["DOWN", "DOWN", "DOWN", "OK"], None, wait=1.0)
    shot("e03-createap-busy"); time.sleep(4); shot("e04-createap-after")
    drive(["BACK"], None, wait=0.5)

    step("Send Beacon  [TX]")
    drive(["DOWN", "DOWN", "DOWN", "DOWN", "OK"], None, wait=1.0)
    shot("e05-beacon-busy"); time.sleep(4); shot("e06-beacon-after")
    drive(["BACK"], None, wait=0.5)

    step("Load Portal -> open first portal file")
    drive(["DOWN", "DOWN", "DOWN", "DOWN", "DOWN", "OK"], "e07-portal-list")
    drive(["OK"], "e08-portal-open")
    drive(["BACK", "BACK"], None, wait=0.4)

    step("AP info: OK = Deauth toggle")
    drive(["DOWN", "OK"], "e09-list")
    drive(["OK"], "e10-info")
    drive(["OK"], "e11-info-deauth")
    step("AP info: RIGHT = Evil")
    drive(["RIGHT"], "e12-info-evil")
    drive(["BACK", "BACK", "BACK"], None, wait=0.4)


def phase_tools():
    step("[setup] hub -> List -> AP info -> Edit -> config -> Tools")
    drive(["OK"], None, wait=0.8)                                  # hub
    drive(["DOWN", "OK"], None, wait=1.2)                          # List
    drive(["OK"], None, wait=1.0)                                  # AP info
    drive(["LEFT"], None, wait=0.8)                                # attack config
    drive(["DOWN", "DOWN", "DOWN", "OK"], "f00-tools")             # Tools

    def tool(pos, name, wait=1.5, after=12):
        step(f"Tools #{pos}: {name}")
        drive(["OK"], None, wait=wait) if pos == 0 else drive(["DOWN"] * pos + ["OK"], None, wait=wait)
        shot(f"f{pos:02d}-{name.split()[0].lower()}-busy")
        time.sleep(after)
        shot(f"f{pos:02d}-{name.split()[0].lower()}-after")
        drive(["BACK"], None, wait=0.6)

    tool(1, "Grab HS (deauth) [TX]", after=14)
    tool(2, "PMKID (passive)", after=10)
    tool(3, "PMKID grab (deauth) [TX]", after=14)
    tool(4, "PMKID clientless (raw) [TX]", after=12)
    tool(5, "Capture_STOP")
    tool(6, "Guided audit [TX]", after=16)
    tool(7, "PMF_WPA3 scan", after=10)
    tool(8, "STASCAN", after=10)
    tool(9, "Deauth_list_+AP")
    tool(10, "Deauth_list_RUN [TX]", after=5)
    tool(11, "Deauth_list_STOP")
    tool(13, "Stop_clear")
    # Channel hop LAST (known hang -> recovery)
    step("Tools #12: Channel hop on/off  [KNOWN HANG]")
    drive(["DOWN"] * 12 + ["OK"], None, wait=2.0)
    shot("f12-hop")
    log("    (hang expected -> reboot + relaunch)")
    subprocess.run([PY, os.path.join(HERE, "flip_reboot.py")], capture_output=True, text=True, timeout=30)
    time.sleep(5)
    launch()


def phase_ble():
    step("BLE hub (main grid: RIGHT + OK)")
    drive(["RIGHT", "OK"], "g00-blehub")
    names = ["BLE_Scan", "iBeacon_1", "iBeacon_2", "BadBLE_1", "BadBLE_2",
             "BLE_Adv_1", "BLE_Adv_2", "Saved_adverts"]
    for i, nm in enumerate(names):
        step(f"BLE item {i}: {nm}")
        drive(["DOWN"] * i + ["OK"], None, wait=1.5) if i else drive(["OK"], None, wait=1.5)
        shot(f"g{i:02d}-{nm.lower()}-busy")
        time.sleep(7)
        shot(f"g{i:02d}-{nm.lower()}-after")
        drive(["BACK", "BACK"], None, wait=0.5)


def phase_exit():
    step("Exit app (main grid: DOWN to Help, RIGHT to Exit, OK)")
    drive(["DOWN", "RIGHT", "OK"], "h00-exit")
    time.sleep(1.5)
    shot("h01-desktop")
    log("    loader info -> " + cli("loader info").strip().splitlines()[-1])


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "all"
    log(f"================ UNTESTED SUITE phase={phase} ================")
    if phase in ("wifi", "all"):
        setup_scan();  phase_wifi()
    if phase in ("tools", "all"):
        setup_scan();  phase_tools()
    if phase in ("ble", "exit", "all"):
        launch();      phase_ble()
    if phase in ("exit", "all"):
        launch();      phase_exit()
    log("================ UNTESTED SUITE done ================")


if __name__ == "__main__":
    main()
