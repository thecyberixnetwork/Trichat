#include "stun.h"
#include <stdio.h>

int main(void) {
    int rc = stun_selftest();
    if (rc != 0) { printf("FAIL: stun codec self-test (code %d)\n", rc); return 1; }
    printf("PASS: stun codec self-test (RFC 2202 HMAC + CRC32 vectors, build/parse round-trips)\n");
    return 0;
}
