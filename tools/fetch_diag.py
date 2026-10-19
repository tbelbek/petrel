import pathlib, re, sys, time, serial
out = pathlib.Path(sys.argv[1])
s = serial.Serial("/dev/cu.usbmodemflip_Uy0th11", 115200, timeout=0.2, write_timeout=5)
try:
    time.sleep(0.4); s.write(b"\r"); time.sleep(0.3); s.read(65536)
    s.write(b"storage read /ext/petrel/diag.txt\r")
    header = bytearray(); deadline = time.monotonic() + 10; match = None
    while time.monotonic() < deadline:
        header += s.read(1)
        m = re.search(rb"Size: (\d+)\r?\n", header)
        if m: match = m; break
    if not match: raise RuntimeError("Size header yok: " + repr(bytes(header)))
    size = int(match.group(1))
    data = bytearray(); dl = time.monotonic() + max(30, size/2000)
    while len(data) < size and time.monotonic() < dl:
        data += s.read(min(4096, size - len(data)))
    if len(data) != size: raise RuntimeError(f"Eksik: {len(data)}/{size}")
    out.write_bytes(data)
    out.with_suffix(out.suffix + ".size").write_text(str(size) + "\n")
    print("ok:", size, "bayt ->", out)
finally:
    s.close()
