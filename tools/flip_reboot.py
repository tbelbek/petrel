#!/usr/bin/env python3
"""flip_reboot - reboot the Flipper over RPC (Main.system_reboot_request, field 31)."""
import time
import flipctl as F

s = F.connect()
try:
    F.send(s, b"\xFA\x01\x00")  # system_reboot_request
    print("reboot sent")
    time.sleep(0.5)
except Exception as e:
    print("err", e)
finally:
    try:
        F.close_session(s)
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass
