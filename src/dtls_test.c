#include "dtls.h"
#include <stdio.h>

int main(void) {
    int rc = dtls_srtp_selftest();
    if (rc != 0) { printf("FAIL: dtls-srtp self-test (code %d)\n", rc); return 1; }
    printf("PASS: dtls-srtp self-test (self-signed cert, DTLS handshake, fingerprint + SRTP key export)\n");
    return 0;
}
