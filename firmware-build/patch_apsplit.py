#!/usr/bin/env python3
"""D.4/2 - dedicated open test-AP entry points in the core (architect's directive).

NOTE (architect's later ruling, link-map evidence): the wifi_conf.c split is WITHDRAWN. The pinned
core never compiles system/component/common/api/wifi/wifi_conf.c - wifi_on/wifi_off come from the
PREBUILT archive lib_arduino.a(wifi_conf.o) - so patching that source cannot change the image. The
lifecycle instead runs the prebuilt blocking calls on a serialized worker task (sketch side).

This script now only adds, to cores/ambd/wifi_drv.cpp (which IS compiled into core.a):
  petrel_ap_begin() / petrel_ap_poll()   - dedicated open test-AP path: no wifiDriverInit, no Arduino
                                         retries, no automatic SDK DHCP; legacy apActivate untouched
  petrel_radio_cache()                  - keeps Arduino's private mode cache consistent after an
                                         explicit radio transition

Idempotent. Usage: patch_apsplit.py <core root, .../AmebaD/<ver>>
"""
import os
import sys

root = sys.argv[1]
wifi_drv = os.path.join(root, "cores", "ambd", "wifi_drv.cpp")


def patch_group(path, marker, steps):
    """Apply a group of steps to one file. The marker says the whole group is in."""
    s = open(path, encoding="utf-8").read()
    if marker in s:
        print("already patched:", os.path.basename(path), f"({len(steps)} steps)")
        return
    for name, old, new in steps:
        if s.count(old) != 1:
            raise SystemExit(f"ANCHOR FAIL ({name}): count={s.count(old)} in {path}")
    # every anchor verified before the first write, so a failure cannot leave a half-applied group
    for name, old, new in steps:
        s = s.replace(old, new)
        print("patched:", name)
    open(path, "w", encoding="utf-8").write(s)


# ---------- wifi_drv.cpp: dedicated open test-AP path ----------
DRV_ANCHOR = "int8_t WiFiDrv::apActivate(uint8_t hidden_ssid) {\n"
DRV_NEW = '''\
/*
 * Dedicated open test-AP path (petrel D.4/2).
 * No wifiDriverInit(), Arduino AP retries, or automatic SDK DHCP.
 * Caller owns ssid until confirmation/cleanup completes.
 */
extern "C" int petrel_ap_begin(char *ssid, unsigned char channel)
{
\t/* 2.4 GHz (1-14) and non-DFS 5 GHz (36-48 UNII-1, 149-165 UNII-3). 5 GHz raw TX is confirmed
\t * on this part by RF ground truth, so 5 GHz SoftAP is attempted; DFS (52-144) is refused (AP
\t * hosting on radar channels is not allowed). The RAW wifi_start_ap return code is returned so
\t * the caller can surface a band/driver refusal instead of silently dropping to 2.4. */
\tif (!ssid)
\t\treturn -1;
\tint ok24 = (channel >= 1 && channel <= 14);
\tint ok5  = (channel >= 36 && channel <= 48) || (channel >= 149 && channel <= 165);
\tif (!ok24 && !ok5)
\t\treturn -1;

\treturn wifi_start_ap(
\t\tssid, RTW_SECURITY_OPEN, NULL,
\t\tstrlen(ssid), 0, channel
\t);
}

extern "C" int petrel_ap_poll(const char *ssid, unsigned char channel)
{
\trtw_wifi_setting_t setting;
\tmemset(&setting, 0, sizeof(setting));

\tif (wifi_get_setting(WLAN0_NAME, &setting) != 0)
\t\treturn 0;

\tif (setting.mode != RTW_MODE_AP ||
\t\tsetting.channel != channel ||
\t\tmemcmp(setting.ssid, ssid, strlen(ssid) + 1) != 0)
\t\treturn 0;

\treturn 1;
}

/* Keep Arduino's private cache consistent after our explicit transition. */
extern "C" void petrel_radio_cache(rtw_mode_t mode)
{
\tinit_wlan = true;
\twifi_mode = mode;
\tarduino_wifi_mode_check =
\t\tmode == RTW_MODE_AP ? 0x10 :
\t\tmode == RTW_MODE_STA_AP ? 0x11 : 0x00;
}

int8_t WiFiDrv::apActivate(uint8_t hidden_ssid) {
'''

patch_group(
    wifi_drv, "petrel_ap_begin",
    [
        ("petrel_ap_* entry points", DRV_ANCHOR, DRV_NEW),
    ])

print("patch_apsplit: done")
