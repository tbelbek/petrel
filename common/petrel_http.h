// Pure predicates shared by the firmware and the host tests (no lwIP, no Arduino).
//
// These decide three things that are easy to get subtly wrong and impossible to unit-test once they
// are buried in a .cpp that needs lwIP headers:
//   - which request paths are OS connectivity probes,
//   - which query strings are credential submissions (vs incidental parameters),
//   - which channels exist for TX.
#ifndef PETREL_HTTP_H
#define PETREL_HTTP_H

#include <stddef.h>
#include <string.h>

// OS captive-portal detection URLs. Substring match: the probes are always the tail of the path
// (/generate_204, /connecttest.txt, /hotspot-detect.html, ...).
static inline int petrel_is_probe_path(const char* path) {
    static const char* pr[] = {"generate_204", "gen_204", "ncsi", "hotspot",
                               "connecttest", "success", "redirect", "canonical"};
    if (!path) return 0;
    for (unsigned i = 0; i < sizeof(pr) / sizeof(pr[0]); i++)
        if (strstr(path, pr[i])) return 1;
    return 0;
}

// 1 when the probe validates a body rather than an empty 204 (Windows).
static inline int petrel_probe_wants_body(const char* path) {
    if (!path) return 0;
    return strstr(path, "connecttest") || strstr(path, "ncsi");
}

// Known credential field names. Brand portals differ, so the list is broad; the match is exact
// (case-insensitive) on the key, never a substring of the whole query.
static inline int petrel_key_is_cred(const char* k, size_t n) {
    static const char* keys[] = {"user", "pass", "pwd", "email", "mail", "login", "name",
                                 "username", "password", "userid", "loginid"};
    // "login[email]=" and its form-encoded "login%5Bemail%5D=" both reduce to the key "login".
    for (size_t i = 0; i < n; i++) {
        if (k[i] == '[') { n = i; break; }
        if (k[i] == '%' && i + 2 < n && k[i + 1] == '5' && (k[i + 2] == 'B' || k[i + 2] == 'b')) {
            n = i; break;
        }
    }
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        size_t kl = strlen(keys[i]);
        if (kl != n) continue;
        size_t j = 0;
        for (; j < n; j++) {
            char a = k[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (a != keys[i][j]) break;
        }
        if (j == n) return 1;
    }
    return 0;
}

// A query string is a credential submission when at least one "key=value" pair has a known key and a
// non-empty value. "?id=123" and "?redirect=1" are not; "?user=a&pass=b" is.
static inline int petrel_is_cred_submit(const char* q) {
    if (!q) return 0;
    const char* p = q;
    while (*p) {
        const char* amp = strchr(p, '&');
        const char* end = amp ? amp : p + strlen(p);
        const char* eq = (const char*)memchr(p, '=', (size_t)(end - p));
        if (eq && eq > p && eq + 1 < end && petrel_key_is_cred(p, (size_t)(eq - p))) return 1;
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

// Channels that exist for TX: 2.4 GHz 1-14 and the non-DFS 5 GHz sets 36-48 / 149-165. A plain range
// check also accepts 15-35, 49-51, 145-148 and 166+.
static inline int petrel_chan_valid(int ch) {
    if (ch >= 1 && ch <= 14) return 1;
    if (ch == 36 || ch == 40 || ch == 44 || ch == 48) return 1;
    if (ch == 149 || ch == 153 || ch == 157 || ch == 161 || ch == 165) return 1;
    return 0;
}

#endif
