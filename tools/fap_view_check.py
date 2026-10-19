#!/usr/bin/env python3
"""Audit the FAP for the "touch the active view from its own dispatch" crash class.

Three real crashes in this project had the same root cause: mutating the view/submenu that is
currently dispatching an event, from inside that dispatch. Concretely:

  1. view_set_input_callback() on the widget view crashed because the widget had no context
     (view_set_context was never called) -> NULL deref in the callback.
  2. Rebuilding the submenu from inside its own item callback left it walking a freed model and
     crashed on the next key.
  3. Installing/clearing the KARMA input callback in scene on_enter/on_exit crashed because
     on_exit runs inside the view's own input dispatch.

The safe shapes are: build/modify views in scene `on_enter` (or a build helper called from there
or from `on_event`), and let UART-thread handlers post custom events instead of pushing scenes.

Usage: python3 fap_view_check.py [path-to-petrelrtl.c]
"""
import re
import sys
from collections import Counter

FN = re.compile(r"^(?:static\s+)?(?:void|bool|int|uint32_t)\s+([A-Za-z_][\w]*)\s*\(")
TOUCH = re.compile(
    r"(submenu_reset|widget_reset|widget_add_\w+|with_view_model|view_dispatcher_switch_to_view)\s*\(")
SCENE = re.compile(r"(scene_manager_next_scene|scene_manager_previous_scene)\s*\(")
# Indirect view rebuild: a scene on_enter() that starts with variable_item_list_reset()/etc. Calling
# one of these from a change callback frees the list the callback is dispatching from - the bug class
# that rebooted the device. The direct-call regex above does NOT catch it (real gap: this checker
# reported clean while security_change_callback called config_ap_scene_on_enter and reset its own
# list), so match the helper call too.
REBUILD = re.compile(r"([A-Za-z_][\w]*)_scene_on_enter\s*\(")
EVT_DEF = re.compile(r"^\s*#define\s+(PETREL_EVT_\w+)\s+(0x[0-9A-Fa-f]+)\b")

# Functions that legitimately touch a view outside a scene transition.
# animation_timer_callback USED to be listed here: it built the RickRoll frame from the timer
# thread, mutating the shared widget. It now posts PETREL_EVT_ANIM_TICK and the frame is built in
# beacon_info_scene_on_event, so it is deliberately no longer exempt - a timer callback that
# touches a view again will fail this check.
KNOWN_OK = {
    "Petrel_custom_callback",   # GUI thread, between frames (view dispatcher callback)
}


def is_callback(name):
    return name.endswith("_cb") or name.endswith("_callback") or name.endswith("call_back")


def strip_comments(lines):
    """Drop C comments so a *_scene_on_enter() mentioned in a comment is not flagged as a call.

    Light quote handling: a // inside a string literal (the portal "http://..." URLs) must not
    start a comment, or the rest of that line disappears from the audit.
    """
    out = []
    in_block = False
    for line in lines:
        res = []
        i = 0
        n = len(line)
        while i < n:
            if in_block:
                j = line.find("*/", i)
                if j < 0:
                    i = n
                    break
                in_block = False
                i = j + 2
                continue
            c = line[i]
            if c == '"':
                res.append(c)
                i += 1
                while i < n:
                    if line[i] == "\\":
                        res.append(line[i:i + 2])
                        i += 2
                        continue
                    res.append(line[i])
                    if line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if c == "/" and i + 1 < n and line[i + 1] == "/":
                break
            if c == "/" and i + 1 < n and line[i + 1] == "*":
                in_block = True
                i += 2
                continue
            res.append(c)
            i += 1
        out.append("".join(res))
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "../flipper-app/petrelrtl.c"
    src = open(path, encoding="utf-8", errors="replace").read().splitlines()
    src = strip_comments(src)

    fn = None
    touches, scenes, rebuilds = [], [], []
    in_uart = False
    for i, line in enumerate(src, 1):
        m = FN.match(line)
        if m:
            fn = m.group(1)
            in_uart = fn == "uart_process_line"
        if fn and TOUCH.search(line):
            touches.append((i, fn, TOUCH.search(line).group(1)))
        if fn and REBUILD.search(line) and is_callback(fn) and \
                REBUILD.search(line).group(1) + "_scene_on_enter" != fn:
            rebuilds.append((i, fn, REBUILD.search(line).group(0).strip("(")))
        if fn and in_uart and SCENE.search(line):
            scenes.append((i, fn, SCENE.search(line).group(1)))

    problems = 0
    print("=== view touched inside a callback? ===")
    for lineno, name, kind in touches:
        if is_callback(name) and name not in KNOWN_OK:
            print(f"  RISK  line {lineno}: {kind} called from {name} (inside a callback)")
            problems += 1
    if not problems:
        print("  clean (only the known-safe callbacks touch a view)")

    print("=== indirect rebuild: a change callback calling <x>_scene_on_enter()? ===")
    if rebuilds:
        for lineno, name, call in rebuilds:
            print(f"  RISK  line {lineno}: {call}() called from {name} - resets the list it is "
                  f"dispatching from; post a custom event instead")
        problems += len(rebuilds)
    else:
        print("  clean (callbacks post PETREL_EVT_REBUILD_VIL / custom events instead)")

    print("=== duplicate PETREL_EVT_* ids? ===")
    ids = {}
    for i, line in enumerate(src, 1):
        m = EVT_DEF.match(line)
        if m:
            ids.setdefault(m.group(2).lower(), []).append((i, m.group(1)))
    dupes = {v: d for v, d in ids.items() if len(d) > 1}
    if dupes:
        for val, defs in sorted(dupes.items()):
            names = ", ".join(f"{n} (line {l})" for l, n in defs)
            print(f"  RISK  {val} defined {len(defs)} times: {names} -> a stale event is decoded "
                  f"by the wrong scene")
            problems += 1
    else:
        print(f"  clean ({len(ids)} unique PETREL_EVT_* ids)")

    print("=== scene pushed straight from uart_process_line? ===")
    if scenes:
        for lineno, name, kind in scenes:
            print(f"  RISK  line {lineno}: {kind} in {name} (UART worker thread)")
        problems += len(scenes)
    else:
        print("  clean (handlers post custom events instead)")

    print()
    print("=== where views are built (should be on_enter / build helpers / on_event) ===")
    for (name, kind), n in sorted(Counter((f, k) for _, f, k in touches).items()):
        print(f"  {name:44s} {kind:24s} x{n}")

    print()
    print(f"{len(touches)} view-touch call sites, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
