// petrel_audit_method — guided-audit method selection (PMF- and station-aware).
//
// Pure logic, NO Flipper/Arduino deps, so it host-compiles for an offline unit test
// (common/petrel_audit_method_test.c). Given what a PMFSCAN + STASCAN learned about the selected
// AP, it picks how to capture crackable material:
//
//   - PMF REQUIRED (802.11w mfp=req, i.e. WPA3-only or a WPA2 AP that mandates management-frame
//     protection): a deauth cannot kick a client to force a fresh 4-way handshake, so go clientless
//     and pull the PMKID from the AP's own M1  -> PMKID.
//   - PMF capable-but-not-required, or no PMF: the AP can still be deauthed. If it HAS associated
//     stations, deauth-assisted handshake capture is the strong play -> HANDSHAKE. With NO stations
//     there is nobody to deauth, so fall back to clientless PMKID -> PMKID.
//
// When the PMFSCAN did not see the target (pmf_seen=false), fall back to the coarse security-bit
// hint (sec_pmf = AP advertised WPA3 / AES-CMAC) for the PMF-required question. Same table, just a
// weaker source for the one input.
#ifndef PETREL_AUDIT_METHOD_H
#define PETREL_AUDIT_METHOD_H
#include <stdbool.h>

typedef enum {
    AUDIT_METHOD_HANDSHAKE = 0, // deauth-assisted 4-way handshake (HSGRAB)
    AUDIT_METHOD_PMKID = 1,     // clientless PMKID (PMKIDCLIENT)
} AuditMethod;

// pmf_seen : the PMFSCAN produced a PMF: line for the target BSSID
// pmf_req  : that line said mfp=req (PMF mandatory)   -- only meaningful when pmf_seen
// sec_pmf  : fallback hint from the scan security bits (WPA3 / AES-CMAC present)
// stas     : stations seen associated to the target in the (BSSID-filtered) STASCAN
static inline AuditMethod audit_pick_method(bool pmf_seen, bool pmf_req, bool sec_pmf, int stas) {
    bool pmf_required = pmf_seen ? pmf_req : sec_pmf;
    // PMF-required -> deauth is useless -> PMKID. No stations -> nobody to deauth -> PMKID.
    // Otherwise (deauthable AND has clients) -> handshake.
    return (pmf_required || stas <= 0) ? AUDIT_METHOD_PMKID : AUDIT_METHOD_HANDSHAKE;
}

#endif // PETREL_AUDIT_METHOD_H
