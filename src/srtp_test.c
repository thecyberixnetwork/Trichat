#include "srtp.h"
#include <stdio.h>

int main(void) {
    int rc = srtp_selftest();
    if (rc != 0) { printf("FAIL: srtp self-test (code %d)\n", rc); return 1; }
    printf("PASS: srtp self-test (RFC 3711 KDF + AES-CM vectors, protect/unprotect round-trip)\n");
    return 0;
}
