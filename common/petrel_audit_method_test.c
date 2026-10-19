// Host self-test for audit_pick_method (guided-audit method selection).
// Build: cc -O2 -Wall -I../flipper-app petrel_audit_method_test.c -o t && ./t
#include "petrel_audit_method.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    // --- PMF seen on the target --------------------------------------------------------------
    // mfp=req -> PMF mandatory -> deauth useless -> PMKID, regardless of stations.
    assert(audit_pick_method(true, true, false, 0) == AUDIT_METHOD_PMKID);
    assert(audit_pick_method(true, true, false, 5) == AUDIT_METHOD_PMKID);
    assert(audit_pick_method(true, true, true, 9) == AUDIT_METHOD_PMKID);

    // PMF capable-but-not-required (mfp=cap, pmf_req=false): deauthable -> station-driven.
    assert(audit_pick_method(true, false, false, 0) == AUDIT_METHOD_PMKID);     // no clients
    assert(audit_pick_method(true, false, false, 1) == AUDIT_METHOD_HANDSHAKE); // has clients
    assert(audit_pick_method(true, false, false, 3) == AUDIT_METHOD_HANDSHAKE);
    // sec_pmf hint is IGNORED once the scan actually saw the AP (pmf_seen wins).
    assert(audit_pick_method(true, false, true, 2) == AUDIT_METHOD_HANDSHAKE);

    // --- PMF NOT seen -> fall back to the security-bit hint ----------------------------------
    // sec_pmf true (AP advertised WPA3/AES-CMAC) -> treat as PMF-required -> PMKID.
    assert(audit_pick_method(false, false, true, 0) == AUDIT_METHOD_PMKID);
    assert(audit_pick_method(false, false, true, 7) == AUDIT_METHOD_PMKID);
    // pmf_req is dead input when pmf_seen=false: the hint alone decides the PMF question.
    assert(audit_pick_method(false, true, false, 4) == AUDIT_METHOD_HANDSHAKE);

    // sec_pmf false (plain WPA2) -> station-driven.
    assert(audit_pick_method(false, false, false, 0) == AUDIT_METHOD_PMKID);     // no clients
    assert(audit_pick_method(false, false, false, 1) == AUDIT_METHOD_HANDSHAKE); // has clients

    // Negative / wildcard station counts are treated as "no stations".
    assert(audit_pick_method(false, false, false, -1) == AUDIT_METHOD_PMKID);

    printf("petrel_audit_method: all cases passed\n");
    return 0;
}
