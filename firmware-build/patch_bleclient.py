#!/usr/bin/env python3
"""Expose the discovered BLE tree (service/characteristic UUIDs) so petrel can show it on the
Flipper instead of the SDK's printServices() (which only goes to the USB log).

BLEClient already owns _servicePtrList/_serviceCount and is a `friend class` of
BLERemoteService, so small inline public accessors in BLEClient.h can read the private lists.
Idempotent.

Usage: patch_bleclient.py <.../libraries/BLE/src>
"""
import os
import sys

src = sys.argv[1]
h = os.path.join(src, "BLEClient.h")

MARKER = "petrel: enumerate discovered services"

ADD = """        // petrel: enumerate discovered services (private lists exposed for the host UI)
        uint8_t getServiceCount() { return _serviceCount; }
        const char* getServiceUuid(uint8_t i) {
            return (i < _serviceCount) ? _servicePtrList[i]->_uuid.str() : "";
        }
        uint8_t getCharacteristicCount(uint8_t i) {
            return (i < _serviceCount) ? _servicePtrList[i]->_characteristicCount : 0;
        }
        const char* getCharacteristicUuid(uint8_t i, uint8_t j) {
            if(i >= _serviceCount) return "";
            BLERemoteService* s = _servicePtrList[i];
            return (j < s->_characteristicCount) ? s->_characteristicPtrList[j]->_uuid.str() : "";
        }
"""

s = open(h).read()
if MARKER in s:
    print("already patched:", os.path.basename(h))
    sys.exit(0)

anchor = "        BLERemoteService* getService(BLEUUID uuid);\n"
if anchor not in s:
    print("ERROR: anchor not found in BLEClient.h", file=sys.stderr)
    sys.exit(1)

s = s.replace(anchor, anchor + ADD, 1)
open(h, "w").write(s)
print("patched:", os.path.basename(h))
