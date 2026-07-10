#include "rtph264.h"
#include <string.h>

int h264_nal_type(const uint8_t *nal, int nlen) { return nlen >= 1 ? (nal[0] & 0x1f) : -1; }

int h264_packetize(const uint8_t *nal, int nlen, int mtu, h264_frag *out, int maxfrag) {
    if (!nal || nlen < 1 || mtu <= 2 || !out) return -1;
    if (nlen <= mtu) {
        out[0].len = nlen; memcpy(out[0].data, nal, (size_t)nlen);
        return 1;
    }

    uint8_t fu_ind = (uint8_t)((nal[0] & 0xE0) | 28);
    uint8_t type   = (uint8_t)(nal[0] & 0x1f);
    const uint8_t *pl = nal + 1; int plen = nlen - 1;
    int chunk = mtu - 2, n = 0, off = 0;
    while (off < plen) {
        if (n >= maxfrag) return -1;
        int take = plen - off; if (take > chunk) take = chunk;
        h264_frag *f = &out[n];
        f->data[0] = fu_ind;
        f->data[1] = (uint8_t)((off == 0 ? 0x80 : 0) | (off + take >= plen ? 0x40 : 0) | type);
        memcpy(f->data + 2, pl + off, (size_t)take);
        f->len = take + 2;
        off += take; n++;
    }
    return n;
}

static int find_startcode(const uint8_t *b, int len, int from) {
    for (int i = from; i + 3 <= len; i++)
        if (b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1) return i;
    return -1;
}

int h264_feed(h264_reader *r, const uint8_t *in, int inlen,
              void (*cb)(void *ud, const uint8_t *nal, int nlen), void *ud) {
    if (!r || !in || inlen < 0) return -1;
    if (r->len + inlen > (int)sizeof r->buf) { r->len = 0; return -1; }
    memcpy(r->buf + r->len, in, (size_t)inlen); r->len += inlen;

    int emitted = 0;
    for (;;) {
        int sc0 = find_startcode(r->buf, r->len, 0);
        if (sc0 < 0) { if (r->len > 3) { memmove(r->buf, r->buf + r->len - 3, 3); r->len = 3; } break; }
        int nal_start = sc0 + 3;
        int sc1 = find_startcode(r->buf, r->len, nal_start);
        if (sc1 < 0) {
            if (sc0 > 0) { memmove(r->buf, r->buf + sc0, (size_t)(r->len - sc0)); r->len -= sc0; }
            break;
        }
        int nal_end = sc1;
        if (nal_end > nal_start && r->buf[nal_end - 1] == 0) nal_end--;
        if (nal_end > nal_start && cb) { cb(ud, r->buf + nal_start, nal_end - nal_start); emitted++; }
        memmove(r->buf, r->buf + sc1, (size_t)(r->len - sc1)); r->len -= sc1;
    }
    return emitted;
}

static int emit_annexb(uint8_t *out, int out_cap, int *o, const uint8_t *nal, int nlen) {
    if (nlen <= 0 || *o + 4 + nlen > out_cap) return -1;
    out[(*o)++] = 0; out[(*o)++] = 0; out[(*o)++] = 0; out[(*o)++] = 1;
    memcpy(out + *o, nal, (size_t)nlen); *o += nlen;
    return 0;
}

int h264_depacketize(h264_depacketizer *d, const uint8_t *pl, int plen, uint8_t *out, int out_cap) {
    if (!d || !pl || plen < 1 || !out || out_cap < 5) return 0;
    int type = pl[0] & 0x1f, o = 0;
    if (type >= 1 && type <= 23)
        return emit_annexb(out, out_cap, &o, pl, plen) < 0 ? -1 : o;
    if (type == 24) {
        int i = 1;
        while (i + 2 <= plen) {
            int sz = (pl[i] << 8) | pl[i + 1]; i += 2;
            if (sz <= 0 || i + sz > plen) break;
            if (emit_annexb(out, out_cap, &o, pl + i, sz) < 0) return -1;
            i += sz;
        }
        return o;
    }
    if (type == 28) {
        if (plen < 2) return 0;
        int s = pl[1] & 0x80, e = pl[1] & 0x40;
        if (s) {
            d->len = 0; d->active = 1;
            d->buf[d->len++] = (uint8_t)((pl[0] & 0xE0) | (pl[1] & 0x1f));
        }
        if (!d->active) return 0;
        int frag = plen - 2;
        if (d->len + frag > (int)sizeof d->buf) { d->active = 0; d->len = 0; return 0; }
        memcpy(d->buf + d->len, pl + 2, (size_t)frag); d->len += frag;
        if (e) {
            int rc = emit_annexb(out, out_cap, &o, d->buf, d->len);
            d->active = 0; d->len = 0;
            return rc < 0 ? -1 : o;
        }
        return 0;
    }
    return 0;
}

static int st_n; static uint8_t st_last[64]; static int st_lastlen;
static void st_cb(void *ud, const uint8_t *nal, int nlen) {
    (void)ud; st_n++; st_lastlen = nlen;
    if (nlen <= (int)sizeof st_last) memcpy(st_last, nal, (size_t)nlen);
}

int h264_selftest(void) {
    uint8_t stream[] = { 0,0,0,1, 0x67,0xAA,0xBB,
                         0,0,1,   0x68,0xCC,
                         0,0,0,1, 0x65,1,2,3,4,5 };
    h264_reader r; h264_reader_reset(&r); st_n = 0;
    if (h264_feed(&r, stream, (int)sizeof stream, st_cb, NULL) != 2) return -1;
    if (h264_feed(&r, (const uint8_t[]){ 0,0,1 }, 3, st_cb, NULL) < 0) return -2;
    if (st_n != 3 || st_lastlen != 6 || st_last[0] != 0x65 || st_last[5] != 5) return -3;
    if (h264_nal_type(st_last, st_lastlen) != 5) return -4;

    uint8_t nal[100]; nal[0] = 0x41; for (int i = 1; i < 100; i++) nal[i] = (uint8_t)i;
    h264_frag fr[H264_MAX_FRAG];
    if (h264_packetize(nal, 100, 1200, fr, H264_MAX_FRAG) != 1 || fr[0].len != 100 || fr[0].data[0] != 0x41) return -5;

    static uint8_t big[5000]; big[0] = 0x65 | 0x60;
    for (int i = 1; i < 5000; i++) big[i] = (uint8_t)(i * 7 + 3);
    int nf = h264_packetize(big, 5000, 1200, fr, H264_MAX_FRAG);
    if (nf < 2) return -6;
    uint8_t re[5100]; int rl = 0;
    for (int i = 0; i < nf; i++) {
        if ((fr[i].data[0] & 0x1f) != 28) return -7;
        if ((fr[i].data[0] & 0xE0) != (big[0] & 0xE0)) return -8;
        int S = fr[i].data[1] & 0x80, E = fr[i].data[1] & 0x40;
        if ((fr[i].data[1] & 0x1f) != (big[0] & 0x1f)) return -9;
        if (i == 0 && !S) return -10;
        if (i == nf - 1 && !E) return -11;
        if (i == 0) { re[0] = big[0]; rl = 1; }
        memcpy(re + rl, fr[i].data + 2, (size_t)(fr[i].len - 2)); rl += fr[i].len - 2;
    }
    if (rl != 5000 || memcmp(re, big, 5000) != 0) return -12;

    h264_depacketizer dp; h264_depkt_reset(&dp);
    static uint8_t ab[6000]; int abn = 0;
    for (int i = 0; i < nf; i++) {
        int w = h264_depacketize(&dp, fr[i].data, fr[i].len, ab + abn, (int)sizeof ab - abn);
        if (w < 0) return -13;
        abn += w;
    }
    if (abn != 4 + 5000 || ab[0] || ab[1] || ab[2] || ab[3] != 1 || memcmp(ab + 4, big, 5000) != 0) return -14;

    h264_depkt_reset(&dp);
    int w1 = h264_depacketize(&dp, nal, 100, ab, (int)sizeof ab);
    if (w1 != 4 + 100 || ab[3] != 1 || ab[4] != 0x41) return -15;
    return 0;
}
