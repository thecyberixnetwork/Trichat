#include "rtph264.h"
#include <stdio.h>

int main(void) {
    int rc = h264_selftest();
    if (rc != 0) { printf("FAIL: h264 rtp self-test (code %d)\n", rc); return 1; }
    printf("PASS: h264 rtp self-test (RFC 6184 Annex-B split + single/FU-A packetize)\n");
    return 0;
}
