#include "rtpvp8.h"
#include <string.h>

int vp8_packetize(const uint8_t *frame, int flen, int payload_mtu, vp8_frag *out, int maxfrag) {
    if (!frame || flen <= 0 || payload_mtu <= 2 || !out) return -1;
    int chunk = payload_mtu - 1;
    int n = 0, off = 0;
    while (off < flen) {
        if (n >= maxfrag) return -1;
        int take = flen - off; if (take > chunk) take = chunk;
        vp8_frag *f = &out[n];
        f->data[0] = (off == 0) ? 0x10 : 0x00;
        memcpy(f->data + 1, frame + off, (size_t)take);
        f->len = take + 1;
        f->marker = (off + take >= flen);
        off += take; n++;
    }
    return n;
}

static int vp8_desc_len(const uint8_t *p, int len) {
    if (len < 1) return -1;
    int n = 1;
    if (p[0] & 0x80) {
        if (len < 2) return -1;
        uint8_t x = p[1]; n = 2;
        if (x & 0x80) {
            if (len < n + 1) return -1;
            n += (p[n] & 0x80) ? 2 : 1;
        }
        if (x & 0x40) n += 1;
        if (x & 0x30) n += 1;
    }
    return n <= len ? n : -1;
}

int vp8_depacketize(vp8_reasm *r, const uint8_t *payload, int plen, int marker,
                    const uint8_t **frame, int *flen) {
    if (!r || !payload || plen < 1) return 0;
    int dl = vp8_desc_len(payload, plen);
    if (dl < 0 || dl >= plen) return 0;
    int start = (payload[0] & 0x10) != 0;
    if (start && (payload[0] & 0x07) == 0) { r->len = 0; r->in_frame = 1; }
    if (!r->in_frame) return 0;
    int datalen = plen - dl;
    if (r->len + datalen > VP8_MAX_FRAME) { r->in_frame = 0; r->len = 0; return 0; }
    memcpy(r->buf + r->len, payload + dl, (size_t)datalen);
    r->len += datalen;
    if (marker) {
        r->in_frame = 0;
        if (frame) *frame = r->buf;
        if (flen) *flen = r->len;
        return 1;
    }
    return 0;
}

int vp8_is_keyframe(const uint8_t *frame, int flen) {
    return flen >= 1 && (frame[0] & 0x01) == 0;
}

int vp8_selftest(void) {
    uint8_t one[100]; for (int i = 0; i < 100; i++) one[i] = (uint8_t)(i * 3 + 1);
    one[0] = 0x00;
    vp8_frag fr[VP8_MAX_FRAG];
    int nf = vp8_packetize(one, 100, 1200, fr, VP8_MAX_FRAG);
    if (nf != 1 || fr[0].len != 101 || fr[0].data[0] != 0x10 || !fr[0].marker) return -1;

    vp8_reasm rs; memset(&rs, 0, sizeof rs);
    const uint8_t *got; int glen;
    if (vp8_depacketize(&rs, fr[0].data, fr[0].len, fr[0].marker, &got, &glen) != 1) return -2;
    if (glen != 100 || memcmp(got, one, 100) != 0) return -3;
    if (!vp8_is_keyframe(got, glen)) return -4;

    static uint8_t big[9000]; for (int i = 0; i < 9000; i++) big[i] = (uint8_t)(i * 7 + 5);
    big[0] = 0x01;
    nf = vp8_packetize(big, 9000, 1200, fr, VP8_MAX_FRAG);
    if (nf < 2) return -5;
    for (int i = 0; i < nf; i++) {
        int wantS = (i == 0) ? 0x10 : 0x00;
        if ((fr[i].data[0] & 0x10) != wantS) return -6;
        if (fr[i].marker != (i == nf - 1)) return -7;
    }
    memset(&rs, 0, sizeof rs);
    int done = 0;
    for (int i = 0; i < nf; i++)
        done = vp8_depacketize(&rs, fr[i].data, fr[i].len, fr[i].marker, &got, &glen);
    if (done != 1 || glen != 9000 || memcmp(got, big, 9000) != 0) return -8;
    if (vp8_is_keyframe(got, glen)) return -9;

    uint8_t ext[10] = { 0x90, 0x80, 0x81, 0x23, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    memset(&rs, 0, sizeof rs);
    if (vp8_depacketize(&rs, ext, 10, 1, &got, &glen) != 1) return -10;
    if (glen != 6 || got[0] != 0xAA || got[5] != 0xFF) return -11;
    return 0;
}
