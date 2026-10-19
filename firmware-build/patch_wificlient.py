#!/usr/bin/env python3
"""Expose the HTTP client's peer IP so petrel can do per-client captive 204.
WiFiClient._sock is a raw lwip socket fd (via ard_socket). We can't include
<lwip/sockets.h> cleanly in WiFiClient.cpp (C++ type clashes), so we add the
lwip call to ard_socket.c (a C file where sockaddr_in already compiles) as
get_peer_ip(fd), and make WiFiClient::remoteIP() call it. Idempotent.

Usage: patch_wificlient.py <.../libraries/WiFi/src>"""
import sys, os
wifi = sys.argv[1]
core = os.path.normpath(os.path.join(wifi, "..", "..", "..", "cores", "ambd"))
ard_h = os.path.join(core, "ard_socket.h")
ard_c = os.path.join(core, "ard_socket.c")
cli_h = os.path.join(wifi, "WiFiClient.h")
cli_c = os.path.join(wifi, "WiFiClient.cpp")


def patch(path, marker, add, mode="append", anchor=None):
    s = open(path).read()
    if marker in s:
        print("already patched:", os.path.basename(path)); return
    if mode == "append":
        s = s.rstrip() + "\n" + add + "\n"
    elif mode == "before":
        s = s.replace(anchor, add + anchor, 1)
    open(path, "w").write(s)
    print("patched:", os.path.basename(path))


# 1) ard_socket.c: lwip getpeername helper (C file -> sockaddr_in compiles here)
patch(ard_c, "get_peer_ip",
      'uint32_t get_peer_ip(int sock) {\n'
      '    struct sockaddr_in a;\n'
      '    socklen_t l = sizeof(a);\n'
      '    if (sock < 0 || lwip_getpeername(sock, (struct sockaddr *)&a, &l) != 0) return 0;\n'
      '    return a.sin_addr.s_addr; /* network byte order */\n'
      '}')

# 2) ard_socket.h: declaration
patch(ard_h, "get_peer_ip", "uint32_t get_peer_ip(int sock);", mode="before",
      anchor="int ota_accept_socket(int server_socket);")

# 3) WiFiClient.h: method declaration
patch(cli_h, "remoteIP", "    IPAddress remoteIP();\n", mode="before",
      anchor="    friend class WiFiServer;")

# 4) WiFiClient.cpp: implementation (no lwip include; call the C helper)
patch(cli_c, "WiFiClient::remoteIP",
      'extern "C" uint32_t get_peer_ip(int sock);\n'
      'IPAddress WiFiClient::remoteIP() {\n'
      '    uint32_t ip = get_peer_ip(_sock);\n'
      '    return IPAddress(ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);\n'
      '}')
