#include "trichat.h"
#include <stdio.h>

int main(void) {
    if (tri_persistence_selftest() != 0) { printf("FAIL: persistence round-trip\n"); return 1; }
    printf("PASS: persistence round-trip (channels.tsv incl. legacy rows + saved.tsv)\n");
    return 0;
}
