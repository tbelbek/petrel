// Host tests for common/petrel_http.h. Build: cc -O2 -Wall -Wextra -o t petrel_http_test.c && ./t
#include "petrel_http.h"
#include <stdio.h>

static int fails = 0, checks = 0;

static void ck(int got, int want, const char* what) {
    checks++;
    if (got != want) { fails++; printf("FAIL %s: got %d want %d\n", what, got, want); }
}

int main(void) {
    // probe paths
    ck(petrel_is_probe_path("/generate_204"), 1, "generate_204");
    ck(petrel_is_probe_path("/gen_204"), 1, "gen_204");
    ck(petrel_is_probe_path("/connecttest.txt"), 1, "connecttest");
    ck(petrel_is_probe_path("/hotspot-detect.html"), 1, "hotspot");
    ck(petrel_is_probe_path("/ncsi.txt"), 1, "ncsi");
    ck(petrel_is_probe_path("/"), 0, "root is not a probe");
    ck(petrel_is_probe_path("/login?user=a"), 0, "login is not a probe");
    ck(petrel_is_probe_path(NULL), 0, "NULL path");

    // probes that validate a body
    ck(petrel_probe_wants_body("/connecttest.txt"), 1, "connecttest wants body");
    ck(petrel_probe_wants_body("/ncsi.txt"), 1, "ncsi wants body");
    ck(petrel_probe_wants_body("/generate_204"), 0, "204 probe wants no body");

    // credential keys
    ck(petrel_key_is_cred("user", 4), 1, "user");
    ck(petrel_key_is_cred("USER", 4), 1, "USER case-insensitive");
    ck(petrel_key_is_cred("Pass", 4), 1, "Pass case-insensitive");
    ck(petrel_key_is_cred("password", 8), 1, "password");
    ck(petrel_key_is_cred("id", 2), 0, "id alone");
    ck(petrel_key_is_cred("xmail", 5), 0, "xmail is not mail");
    ck(petrel_key_is_cred("login[email]", 12), 1, "bracketed key");
    ck(petrel_key_is_cred("login%5Bemail%5D", 16), 1, "percent-encoded bracket");
    ck(petrel_key_is_cred("login%5bemail%5d", 16), 1, "lowercase percent bracket");

    // submissions
    ck(petrel_is_cred_submit("id=123"), 0, "id=123");
    ck(petrel_is_cred_submit("redirect=1"), 0, "redirect=1");
    ck(petrel_is_cred_submit("x=mail"), 0, "x=mail (value, not key)");
    ck(petrel_is_cred_submit("user=a&pass=b"), 1, "user+pass");
    ck(petrel_is_cred_submit("login[email]=x@y"), 1, "bracketed submit");
    ck(petrel_is_cred_submit("login%5Bemail%5D=x%40y"), 1, "encoded submit");
    ck(petrel_is_cred_submit("password="), 0, "empty value");
    ck(petrel_is_cred_submit("user="), 0, "empty user");
    ck(petrel_is_cred_submit("a=1&email=x"), 1, "second pair matches");
    ck(petrel_is_cred_submit("=x"), 0, "empty key");
    ck(petrel_is_cred_submit(""), 0, "empty query");
    ck(petrel_is_cred_submit(NULL), 0, "NULL query");

    // channels
    int good[] = {1, 6, 11, 14, 36, 40, 44, 48, 149, 153, 157, 161, 165};
    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); i++) ck(petrel_chan_valid(good[i]), 1, "valid ch");
    int bad[] = {0, 15, 20, 35, 37, 49, 51, 52, 100, 144, 145, 148, 166, 200, -1};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) ck(petrel_chan_valid(bad[i]), 0, "invalid ch");

    printf("%d/%d checks passed\n", checks - fails, checks);
    return fails ? 1 : 0;
}
