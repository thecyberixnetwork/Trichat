#include "omemo.h"
#include <stdio.h>
#include <string.h>

static int pb_varint(uint8_t *out, size_t cap, size_t *off, uint64_t v) {
    do { if (*off >= cap) return -1;
         uint8_t b = v & 0x7f; v >>= 7; if (v) b |= 0x80; out[(*off)++] = b;
    } while (v);
    return 0;
}
static int pb_key(uint8_t *out, size_t cap, size_t *off, uint32_t field, uint32_t wtype) {
    return pb_varint(out, cap, off, ((uint64_t)field << 3) | wtype);
}
static int pb_uint(uint8_t *out, size_t cap, size_t *off, uint32_t field, uint32_t v) {
    if (pb_key(out, cap, off, field, 0) != 0) return -1;
    return pb_varint(out, cap, off, v);
}
static int pb_bytes(uint8_t *out, size_t cap, size_t *off, uint32_t field, const uint8_t *b, size_t n) {
    if (pb_key(out, cap, off, field, 2) != 0) return -1;
    if (pb_varint(out, cap, off, n) != 0) return -1;
    if (*off + n > cap) return -1;
    memcpy(out + *off, b, n); *off += n;
    return 0;
}

static int pb_pubkey(uint8_t *out, size_t cap, size_t *off, uint32_t field, const uint8_t key[OMEMO_KEY_LEN]) {
    uint8_t djb[1 + OMEMO_KEY_LEN]; djb[0] = OMEMO_DJB_TYPE; memcpy(djb + 1, key, OMEMO_KEY_LEN);
    return pb_bytes(out, cap, off, field, djb, sizeof djb);
}

typedef struct { const uint8_t *p, *end; } pbr;
static int pbr_varint(pbr *r, uint64_t *v) {
    *v = 0; int shift = 0;
    while (r->p < r->end) {
        uint8_t b = *r->p++;
        *v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) return 0;
        shift += 7; if (shift > 63) return -1;
    }
    return -1;
}

static int pbr_tag(pbr *r, uint32_t *field, uint32_t *wtype) {
    if (r->p >= r->end) return -1;
    uint64_t k; if (pbr_varint(r, &k) != 0) return -1;
    *field = (uint32_t)(k >> 3); *wtype = (uint32_t)(k & 7);
    return 0;
}

static int pbr_bytes(pbr *r, const uint8_t **b, size_t *n) {
    uint64_t len; if (pbr_varint(r, &len) != 0) return -1;
    if ((uint64_t)(r->end - r->p) < len) return -1;
    *b = r->p; *n = (size_t)len; r->p += len;
    return 0;
}

static int pbr_skip(pbr *r, uint32_t wtype) {
    if (wtype == 0) { uint64_t v; return pbr_varint(r, &v); }
    if (wtype == 2) { const uint8_t *b; size_t n; return pbr_bytes(r, &b, &n); }
    return -1;
}
static int read_pubkey(pbr *r, uint8_t key[OMEMO_KEY_LEN]) {
    const uint8_t *b; size_t n;
    if (pbr_bytes(r, &b, &n) != 0) return -1;
    if (n != 1 + OMEMO_KEY_LEN || b[0] != OMEMO_DJB_TYPE) return -1;
    memcpy(key, b + 1, OMEMO_KEY_LEN);
    return 0;
}

int omemo_signal_serialize(uint8_t *out, size_t outcap,
        const uint8_t ratchet_pub[OMEMO_KEY_LEN], uint32_t counter, uint32_t prev_counter,
        const uint8_t *ct, size_t ctlen) {
    if (outcap < 1) return -1;
    out[0] = OMEMO_WIRE_VERSION;
    size_t off = 1;
    if (pb_pubkey(out, outcap, &off, 1, ratchet_pub) != 0) return -1;
    if (pb_uint(out, outcap, &off, 2, counter) != 0) return -1;
    if (pb_uint(out, outcap, &off, 3, prev_counter) != 0) return -1;
    if (pb_bytes(out, outcap, &off, 4, ct, ctlen) != 0) return -1;
    return (int)off;
}
int omemo_signal_parse(const uint8_t *in, size_t inlen,
        uint8_t ratchet_pub[OMEMO_KEY_LEN], uint32_t *counter, uint32_t *prev_counter,
        const uint8_t **ct, size_t *ctlen) {
    if (inlen < 1 || in[0] != OMEMO_WIRE_VERSION) return -1;
    pbr r = { in + 1, in + inlen };
    int got_rk = 0, got_ct = 0; *counter = 0; *prev_counter = 0;
    uint32_t field, wt;
    while (pbr_tag(&r, &field, &wt) == 0) {
        if (field == 1 && wt == 2) { if (read_pubkey(&r, ratchet_pub) != 0) return -1; got_rk = 1; }
        else if (field == 2 && wt == 0) { uint64_t v; if (pbr_varint(&r, &v) != 0) return -1; *counter = (uint32_t)v; }
        else if (field == 3 && wt == 0) { uint64_t v; if (pbr_varint(&r, &v) != 0) return -1; *prev_counter = (uint32_t)v; }
        else if (field == 4 && wt == 2) { if (pbr_bytes(&r, ct, ctlen) != 0) return -1; got_ct = 1; }
        else if (pbr_skip(&r, wt) != 0) return -1;
    }
    return (got_rk && got_ct) ? 0 : -1;
}

int omemo_prekey_serialize(uint8_t *out, size_t outcap,
        uint32_t registration_id, uint32_t prekey_id, uint32_t signed_prekey_id,
        const uint8_t base_pub[OMEMO_KEY_LEN], const uint8_t identity_pub[OMEMO_KEY_LEN],
        const uint8_t *inner_msg, size_t inner_len) {
    if (outcap < 1) return -1;
    out[0] = OMEMO_WIRE_VERSION;
    size_t off = 1;
    if (pb_uint(out, outcap, &off, 1, prekey_id) != 0) return -1;
    if (pb_pubkey(out, outcap, &off, 2, base_pub) != 0) return -1;
    if (pb_pubkey(out, outcap, &off, 3, identity_pub) != 0) return -1;
    if (pb_bytes(out, outcap, &off, 4, inner_msg, inner_len) != 0) return -1;
    if (pb_uint(out, outcap, &off, 5, registration_id) != 0) return -1;
    if (pb_uint(out, outcap, &off, 6, signed_prekey_id) != 0) return -1;
    return (int)off;
}
int omemo_prekey_parse(const uint8_t *in, size_t inlen,
        uint32_t *registration_id, uint32_t *prekey_id, uint32_t *signed_prekey_id,
        uint8_t base_pub[OMEMO_KEY_LEN], uint8_t identity_pub[OMEMO_KEY_LEN],
        const uint8_t **inner_msg, size_t *inner_len) {
    if (inlen < 1 || in[0] != OMEMO_WIRE_VERSION) return -1;
    pbr r = { in + 1, in + inlen };
    int got_base = 0, got_ik = 0, got_msg = 0;
    *registration_id = 0; *prekey_id = 0; *signed_prekey_id = 0;
    uint32_t field, wt;
    while (pbr_tag(&r, &field, &wt) == 0) {
        if (field == 1 && wt == 0) { uint64_t v; if (pbr_varint(&r, &v) != 0) return -1; *prekey_id = (uint32_t)v; }
        else if (field == 2 && wt == 2) { if (read_pubkey(&r, base_pub) != 0) return -1; got_base = 1; }
        else if (field == 3 && wt == 2) { if (read_pubkey(&r, identity_pub) != 0) return -1; got_ik = 1; }
        else if (field == 4 && wt == 2) { if (pbr_bytes(&r, inner_msg, inner_len) != 0) return -1; got_msg = 1; }
        else if (field == 5 && wt == 0) { uint64_t v; if (pbr_varint(&r, &v) != 0) return -1; *registration_id = (uint32_t)v; }
        else if (field == 6 && wt == 0) { uint64_t v; if (pbr_varint(&r, &v) != 0) return -1; *signed_prekey_id = (uint32_t)v; }
        else if (pbr_skip(&r, wt) != 0) return -1;
    }
    return (got_base && got_ik && got_msg) ? 0 : -1;
}

int omemo_wire_selftest(void) {
    uint8_t rk[32], bk[32], ik[32]; for (int i = 0; i < 32; i++) { rk[i] = (uint8_t)i; bk[i] = (uint8_t)(0x40 + i); ik[i] = (uint8_t)(0x80 + i); }
    uint8_t ct[50]; for (int i = 0; i < 50; i++) ct[i] = (uint8_t)(0xC0 ^ i);

    uint8_t buf[256];
    int n = omemo_signal_serialize(buf, sizeof buf, rk, 7, 3, ct, sizeof ct);
    if (n < 0) { fprintf(stderr, "wire: signal serialize failed\n"); return -1; }
    if (buf[0] != OMEMO_WIRE_VERSION) { fprintf(stderr, "wire: bad version byte\n"); return -1; }
    uint8_t rk2[32]; uint32_t c, pc; const uint8_t *ct2; size_t ctl2;
    if (omemo_signal_parse(buf, (size_t)n, rk2, &c, &pc, &ct2, &ctl2) != 0) { fprintf(stderr, "wire: signal parse failed\n"); return -1; }
    if (memcmp(rk, rk2, 32) || c != 7 || pc != 3 || ctl2 != sizeof ct || memcmp(ct, ct2, sizeof ct)) {
        fprintf(stderr, "wire: signal round-trip mismatch\n"); return -1; }

    buf[0] = 0x22; if (omemo_signal_parse(buf, (size_t)n, rk2, &c, &pc, &ct2, &ctl2) == 0) { fprintf(stderr, "wire: accepted bad version\n"); return -1; }

    buf[0] = OMEMO_WIRE_VERSION;
    uint8_t pk[400];
    int pn = omemo_prekey_serialize(pk, sizeof pk, 12345, 99, 4, bk, ik, buf, (size_t)n);
    if (pn < 0) { fprintf(stderr, "wire: prekey serialize failed\n"); return -1; }
    uint32_t reg, pkid, spkid; uint8_t bk2[32], ik2[32]; const uint8_t *inner; size_t innerlen;
    if (omemo_prekey_parse(pk, (size_t)pn, &reg, &pkid, &spkid, bk2, ik2, &inner, &innerlen) != 0) { fprintf(stderr, "wire: prekey parse failed\n"); return -1; }
    if (reg != 12345 || pkid != 99 || spkid != 4 || memcmp(bk, bk2, 32) || memcmp(ik, ik2, 32) ||
        innerlen != (size_t)n || memcmp(inner, buf, (size_t)n)) { fprintf(stderr, "wire: prekey round-trip mismatch\n"); return -1; }

    if (omemo_signal_parse(inner, innerlen, rk2, &c, &pc, &ct2, &ctl2) != 0 || c != 7) { fprintf(stderr, "wire: wrapped signal parse failed\n"); return -1; }
    return 0;
}
