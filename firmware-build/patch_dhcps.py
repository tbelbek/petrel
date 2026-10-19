#!/usr/bin/env python3
"""Insert DHCP option 114 (RFC 8910 Captive-Portal) into an AmebaD dhcps.c, idempotently.
Finds the END-option block inside add_offer_options() and inserts the option just before it.
Version-robust: keys off the DHCP_OPTION_CODE_END write, not line numbers."""
import sys, re

path = sys.argv[1]
src = open(path).read()
if "DHO_CAPTIVE_PORTAL" in src:
    print("already patched:", path); sys.exit(0)

INSERT = '''\t/* DHCP option 114 (RFC 8910 Captive-Portal URI) — advertises the portal URL in the
\tlease so Android 11+/iOS fire the sign-in flow without relying on probe interception. */
\t{
\t\tstatic const char captive_uri[] = "http://192.168.1.1/";
\t\tuint8_t uri_len = (uint8_t)(sizeof(captive_uri) - 1);
\t\tif(temp_option_addr + 2 + uri_len - option_start_address <= max_addable_option_len) {
\t\t\t*temp_option_addr++ = 114; /* DHO_CAPTIVE_PORTAL */
\t\t\t*temp_option_addr++ = uri_len;
\t\t\tmemcpy(temp_option_addr, captive_uri, uri_len);
\t\t\ttemp_option_addr += uri_len;
\t\t}
\t}

'''

# Insert before the first "// END" that precedes a DHCP_OPTION_CODE_END write in add_offer_options.
m = re.search(r'\n(\t*// END\n\t*if\([^\n]*max_addable_option_len\) \{\n\t*\*temp_option_addr\+\+ = DHCP_OPTION_CODE_END;)', src)
if not m:
    # fallback: insert before the first standalone END write
    m2 = re.search(r'\n(\t*\*temp_option_addr\+\+ = DHCP_OPTION_CODE_END;)', src)
    if not m2:
        print("!! could not locate END-option insertion point"); sys.exit(1)
    src = src[:m2.start()+1] + INSERT + src[m2.start()+1:]
else:
    src = src[:m.start()+1] + INSERT + src[m.start()+1:]

open(path, "w").write(src)
print("patched option 114 into:", path)
