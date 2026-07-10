#include "ivf.h"
#include <string.h>

static uint32_t rd32le(const uint8_t *b) { return b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24; }

int ivf_feed(ivf_reader *r, const uint8_t *in, int inlen,
             void (*cb)(void *ud, const uint8_t *frame, int flen), void *ud) {
    if (!r || !in || inlen < 0) return -1;
    int emitted = 0, off = 0;
    while (off < inlen) {
        int space = (int)sizeof r->buf - r->len;
        if (space <= 0) { r->len = 0; return -1; }
        int take = inlen - off; if (take > space) take = space;
        memcpy(r->buf + r->len, in + off, (size_t)take);
        r->len += take; off += take;

        for (;;) {
            int consumed = 0;
            if (!r->header_done) {
                if (r->len < 32) break;
                if (memcmp(r->buf, "DKIF", 4) != 0) return -1;
                consumed = 32; r->header_done = 1;
            } else {
                if (r->len < 12) break;
                uint32_t fsz = rd32le(r->buf);
                if (fsz > sizeof r->buf - 12) { r->len = 0; return -1; }
                if (r->len < 12 + (int)fsz) break;
                if (cb) cb(ud, r->buf + 12, (int)fsz);
                emitted++;
                consumed = 12 + (int)fsz;
            }
            memmove(r->buf, r->buf + consumed, (size_t)(r->len - consumed));
            r->len -= consumed;
        }
    }
    return emitted;
}

static int st_count; static uint8_t st_last[64]; static int st_lastlen;
static void st_cb(void *ud, const uint8_t *frame, int flen) {
    (void)ud; st_count++; st_lastlen = flen;
    if (flen <= (int)sizeof st_last) memcpy(st_last, frame, (size_t)flen);
}
static void put32le(uint8_t *b, uint32_t v) { b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24; }

int ivf_selftest(void) {
    uint8_t stream[32 + 12 + 10 + 12 + 20];
    int n = 0;
    memcpy(stream, "DKIF", 4); n = 32;
    put32le(stream + n, 10); memset(stream + n + 4, 0, 8); n += 12;
    for (int i = 0; i < 10; i++) stream[n + i] = (uint8_t)(i + 1);
    n += 10;
    put32le(stream + n, 20); memset(stream + n + 4, 0, 8); n += 12;
    for (int i = 0; i < 20; i++) stream[n + i] = (uint8_t)(i + 100);
    n += 20;

    ivf_reader r; ivf_reset(&r); st_count = 0;
    if (ivf_feed(&r, stream, n, st_cb, NULL) != 2) return -1;
    if (st_count != 2 || st_lastlen != 20 || st_last[0] != 100 || st_last[19] != 119) return -2;

    ivf_reset(&r); st_count = 0;
    for (int i = 0; i < n; i++) if (ivf_feed(&r, stream + i, 1, st_cb, NULL) < 0) return -3;
    if (st_count != 2 || st_lastlen != 20) return -4;

    ivf_reset(&r);
    uint8_t junk[32] = { 'X','X','X','X' };
    if (ivf_feed(&r, junk, 32, st_cb, NULL) != -1) return -5;
    return 0;
}
