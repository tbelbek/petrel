#!/usr/bin/env python3
"""flip_launch - start the FAP and PROVE it is running before anyone sends keys.

Why this exists: `ufbt launch` sometimes fails silently (runbook section 13, pitfall 9: "Device not
configured" / "App Search open") - the install still happens, but the app does not start. Blind key
sequences then drive the DESKTOP instead: pressing OK opens Sub-GHz, DOWN walks its Favorites, and the
screen shows a completely different application. That is exactly how a whole series of "the app went
to the wrong screen" diagnoses happened, and it was never the app.

So: launch, wait, and require the loader to report the app as running. Retry a few times. Only exit 0
when the app is really up, so a caller can `&&` its key sequence on it.

Usage:  python3 flip_launch.py [--name Petrel] [--tries 3] [--wait 5]
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(HERE, "..", "flipper-app")
UFBT_HOME = os.path.expanduser("~/.ufbt-unl")
PY = sys.executable


def arg(flag, default):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else default


def running(name):
    out = subprocess.run(
        [PY, os.path.join(HERE, "flip_cli.py"), "loader info"],
        capture_output=True, text=True, timeout=60).stdout
    return name in out and "is running" in out


def main():
    name = arg("--name", "Petrel")
    tries = int(arg("--tries", "3"))
    wait = float(arg("--wait", "5"))
    env = dict(os.environ, UFBT_HOME=UFBT_HOME)
    # Always launch, even when the app is already up: ufbt launch replaces the running instance
    # ("Closing current app"), and testing a NEW build is exactly why this tool exists. The old
    # "already running -> return 0" shortcut silently verified the previous binary.
    for i in range(1, tries + 1):
        subprocess.run(["ufbt", "launch"], cwd=APP_DIR, env=env,
                       capture_output=True, text=True, timeout=300)
        import time
        time.sleep(wait)
        if running(name):
            print(f"launched ({name}) on try {i}")
            return 0
        print(f"try {i}: ufbt launch did not leave {name} running")
    print("FAILED: app not running after "
          f"{tries} tries - launch it from the file browser "
          "(desktop OK -> Apps -> GPIO -> Petrel) and retry")
    return 1


if __name__ == "__main__":
    sys.exit(main())
