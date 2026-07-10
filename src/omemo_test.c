#include "omemo.h"
#include <stdio.h>

int main(void) {
    if (omemo_selftest() != 0) { printf("FAIL: omemo crypto self-test\n"); return 1; }
    printf("PASS: omemo crypto self-test\n");
    if (omemo_wire_selftest() != 0) { printf("FAIL: omemo wire self-test\n"); return 1; }
    printf("PASS: omemo wire self-test (SignalMessage/PreKeySignalMessage protobuf)\n");
    if (omemo_session_selftest() != 0) { printf("FAIL: omemo session self-test\n"); return 1; }
    printf("PASS: omemo session self-test (X3DH + Double Ratchet, two-party)\n");
    if (omemo_envelope_selftest() != 0) { printf("FAIL: omemo envelope self-test\n"); return 1; }
    printf("PASS: omemo envelope self-test (<encrypted> round-trip + device-list/bundle XML)\n");
    if (omemo_store_selftest() != 0) { printf("FAIL: omemo store self-test\n"); return 1; }
    printf("PASS: omemo store self-test (simulated two-client handshake + persistence)\n");
    return 0;
}
