#include "ivf.h"
#include <stdio.h>

int main(void) {
    int rc = ivf_selftest();
    if (rc != 0) { printf("FAIL: ivf self-test (code %d)\n", rc); return 1; }
    printf("PASS: ivf self-test (header + streaming multi-frame parse)\n");
    return 0;
}
