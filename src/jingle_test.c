#include "jingle.h"
#include <stdio.h>

int main(void) {
    if (jingle_selftest() != 0) { printf("FAIL: jingle signaling self-test\n"); return 1; }
    printf("PASS: jingle signaling self-test (XEP-0166/0167/0176 build->parse round-trip)\n");
    return 0;
}
