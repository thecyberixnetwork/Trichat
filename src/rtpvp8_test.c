#include "rtpvp8.h"
#include <stdio.h>

int main(void) {
    int rc = vp8_selftest();
    if (rc != 0) { printf("FAIL: vp8 rtp self-test (code %d)\n", rc); return 1; }
    printf("PASS: vp8 rtp self-test (RFC 7741 packetize/depacketize + descriptor parse)\n");
    return 0;
}
