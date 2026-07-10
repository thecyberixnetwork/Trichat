#include "ice.h"
#include <stdio.h>

int main(void) {
    int rc = ice_selftest();
    if (rc != 0) { printf("FAIL: ice gathering self-test (code %d)\n", rc); return 1; }
    printf("PASS: ice self-test (loopback gather + two-agent connectivity check to CONNECTED)\n");
    return 0;
}
