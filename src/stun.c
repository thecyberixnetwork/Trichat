#include "stun.h"
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/md5.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static uint32_t crc32(const uint8_t *d, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return c ^ 0xFFFFFFFFu;
}
static int hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t out[20]) {
    Hmac h; if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_HmacSetKey(&h, WC_SHA, key, (word32)klen) == 0 &&
        wc_HmacUpdate(&h, data, (word32)dlen) == 0 &&
        wc_HmacFinal(&h, out) == 0) rc = 0;
    wc_HmacFree(&h);
    return rc;
}

int stun_longterm_key(const char *user, const char *realm, const char *pass, uint8_t out[16]) {
    wc_Md5 h; if (wc_InitMd5(&h) != 0) return -1;
    int rc = -1;
    if (wc_Md5Update(&h, (const byte *)user,  (word32)strlen(user))  == 0 &&
        wc_Md5Update(&h, (const byte *)":",   1)                     == 0 &&
        wc_Md5Update(&h, (const byte *)realm, (word32)strlen(realm)) == 0 &&
        wc_Md5Update(&h, (const byte *)":",   1)                     == 0 &&
        wc_Md5Update(&h, (const byte *)pass,  (word32)strlen(pass))  == 0 &&
        wc_Md5Final(&h, out) == 0) rc = 0;
    wc_Md5Free(&h);
    return rc;
}

void stun_begin(stun_msg *m, uint8_t *buf, size_t cap, uint16_t type, const uint8_t txid[STUN_TXID_LEN]) {
    m->buf = buf; m->cap = cap; m->len = 0; m->err = 0;
    if (cap < STUN_HEADER_LEN) { m->err = 1; return; }
    put16(buf, type); put16(buf + 2, 0); put32(buf + 4, STUN_MAGIC_COOKIE);
    memcpy(buf + 8, txid, STUN_TXID_LEN);
    m->len = STUN_HEADER_LEN;
}
void stun_add_bytes(stun_msg *m, uint16_t type, const void *data, uint16_t len) {
    if (m->err) return;
    size_t pad = (4 - (len & 3)) & 3;
    if (m->len + 4 + len + pad > m->cap) { m->err = 1; return; }
    put16(m->buf + m->len, type); put16(m->buf + m->len + 2, len);
    if (len) memcpy(m->buf + m->len + 4, data, len);
    if (pad) memset(m->buf + m->len + 4 + len, 0, pad);
    m->len += 4 + len + pad;
}
void stun_add_u32(stun_msg *m, uint16_t type, uint32_t v) { uint8_t b[4]; put32(b, v); stun_add_bytes(m, type, b, 4); }
void stun_add_u64(stun_msg *m, uint16_t type, uint64_t v) { uint8_t b[8]; put32(b, (uint32_t)(v >> 32)); put32(b + 4, (uint32_t)v); stun_add_bytes(m, type, b, 8); }
void stun_add_flag(stun_msg *m, uint16_t type) { stun_add_bytes(m, type, NULL, 0); }

void stun_add_xor_addr(stun_msg *m, uint16_t type, const stun_addr *a) {
    uint8_t mc[16]; put32(mc, STUN_MAGIC_COOKIE); memcpy(mc + 4, m->buf + 8, STUN_TXID_LEN);
    int alen = a->family == 6 ? 16 : 4;
    uint8_t v[20];
    v[0] = 0; v[1] = a->family == 6 ? 0x02 : 0x01;
    uint16_t xport = a->port ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
    v[2] = (uint8_t)(xport >> 8); v[3] = (uint8_t)xport;
    for (int i = 0; i < alen; i++) v[4 + i] = a->addr[i] ^ mc[i];
    stun_add_bytes(m, type, v, (uint16_t)(4 + alen));
}

int stun_add_integrity(stun_msg *m, const char *key, size_t keylen) {
    if (m->err || m->len + 24 > m->cap) { m->err = 1; return -1; }
    put16(m->buf + 2, (uint16_t)((m->len - STUN_HEADER_LEN) + 24));
    uint8_t mac[20];
    if (hmac_sha1((const uint8_t *)key, keylen, m->buf, m->len, mac) != 0) { m->err = 1; return -1; }
    stun_add_bytes(m, STUN_ATTR_MESSAGE_INTEGRITY, mac, 20);
    return m->err ? -1 : 0;
}

int stun_add_fingerprint(stun_msg *m) {
    if (m->err || m->len + 8 > m->cap) { m->err = 1; return -1; }
    put16(m->buf + 2, (uint16_t)((m->len - STUN_HEADER_LEN) + 8));
    uint32_t fp = crc32(m->buf, m->len) ^ 0x5354554Eu;
    stun_add_u32(m, STUN_ATTR_FINGERPRINT, fp);
    return m->err ? -1 : 0;
}
int stun_finish(stun_msg *m) {
    if (m->err || m->len < STUN_HEADER_LEN) return -1;
    put16(m->buf + 2, (uint16_t)(m->len - STUN_HEADER_LEN));
    return (int)m->len;
}

int stun_check(const uint8_t *buf, size_t len) {
    if (len < STUN_HEADER_LEN) return 0;
    if ((buf[0] & 0xC0) != 0) return 0;
    if (get32(buf + 4) != STUN_MAGIC_COOKIE) return 0;
    uint16_t mlen = get16(buf + 2);
    if (mlen & 3) return 0;
    return STUN_HEADER_LEN + (size_t)mlen == len;
}
uint16_t stun_type(const uint8_t *buf) { return get16(buf); }
const uint8_t *stun_txid(const uint8_t *buf) { return buf + 8; }

const uint8_t *stun_find(const uint8_t *buf, size_t len, uint16_t type, uint16_t *vlen) {
    if (len < STUN_HEADER_LEN) return NULL;
    size_t off = STUN_HEADER_LEN;
    while (off + 4 <= len) {
        uint16_t at = get16(buf + off), al = get16(buf + off + 2);
        if (off + 4 + al > len) break;
        if (at == type) { if (vlen) *vlen = al; return buf + off + 4; }
        off += 4 + al + ((4 - (al & 3)) & 3);
    }
    return NULL;
}
int stun_get_xor_addr(const uint8_t *buf, size_t len, uint16_t type, stun_addr *out) {
    uint16_t vlen; const uint8_t *v = stun_find(buf, len, type, &vlen);
    if (!v || vlen < 8) return -1;
    out->family = v[1] == 0x02 ? 6 : 4;
    int alen = out->family == 6 ? 16 : 4;
    if (vlen < 4 + alen) return -1;
    out->port = (uint16_t)((v[2] << 8) | v[3]) ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
    uint8_t mc[16]; put32(mc, STUN_MAGIC_COOKIE); memcpy(mc + 4, buf + 8, STUN_TXID_LEN);
    memset(out->addr, 0, sizeof out->addr);
    for (int i = 0; i < alen; i++) out->addr[i] = v[4 + i] ^ mc[i];
    return 0;
}

int stun_error_code(const uint8_t *buf, size_t len) {
    uint16_t vlen; const uint8_t *v = stun_find(buf, len, STUN_ATTR_ERROR_CODE, &vlen);
    if (!v || vlen < 4) return -1;
    return v[2] * 100 + v[3];
}

int stun_verify_integrity(const uint8_t *buf, size_t len, const char *key, size_t keylen) {
    uint16_t vlen; const uint8_t *mi = stun_find(buf, len, STUN_ATTR_MESSAGE_INTEGRITY, &vlen);
    if (!mi || vlen != 20) return -1;
    size_t mi_off = (size_t)(mi - buf) - 4;
    if (mi_off > 1500) return -1;
    uint8_t tmp[1536]; memcpy(tmp, buf, mi_off);
    put16(tmp + 2, (uint16_t)((mi_off - STUN_HEADER_LEN) + 24));
    uint8_t mac[20];
    if (hmac_sha1((const uint8_t *)key, keylen, tmp, mi_off, mac) != 0) return -1;
    return memcmp(mac, mi, 20) == 0 ? 0 : -1;
}
int stun_verify_fingerprint(const uint8_t *buf, size_t len) {
    uint16_t vlen; const uint8_t *fp = stun_find(buf, len, STUN_ATTR_FINGERPRINT, &vlen);
    if (!fp || vlen != 4) return -1;
    size_t fp_off = (size_t)(fp - buf) - 4;
    if (fp_off > 1500) return -1;
    uint8_t tmp[1536]; memcpy(tmp, buf, fp_off);
    put16(tmp + 2, (uint16_t)((fp_off - STUN_HEADER_LEN) + 8));
    return get32(fp) == (crc32(tmp, fp_off) ^ 0x5354554Eu) ? 0 : -1;
}

int stun_selftest(void) {
    if (crc32((const uint8_t *)"123456789", 9) != 0xCBF43926u) return -1;

    uint8_t k[20]; memset(k, 0x0b, 20); uint8_t mac[20];
    static const uint8_t hmwant[20] = { 0xb6,0x17,0x31,0x86,0x55,0x05,0x72,0x64,0xe2,0x8b,
                                        0xc0,0xb6,0xfb,0x37,0x8c,0x8e,0xf1,0x46,0xbe,0x00 };
    if (hmac_sha1(k, 20, (const uint8_t *)"Hi There", 8, mac) != 0 || memcmp(mac, hmwant, 20)) return -2;

    uint8_t txid[12]; for (int i = 0; i < 12; i++) txid[i] = (uint8_t)(i * 7 + 1);
    uint8_t buf[512]; stun_msg m;
    const char *pwd = "VOkJxbRl1RmTxUk/WvJxBt";
    stun_begin(&m, buf, sizeof buf, STUN_BINDING_REQUEST, txid);
    stun_add_bytes(&m, STUN_ATTR_USERNAME, "evtj:h6vY", 9);
    stun_add_u32(&m, STUN_ATTR_PRIORITY, 0x6e0001ffu);
    stun_add_u64(&m, STUN_ATTR_ICE_CONTROLLING, 0x932ff9b151263b36ULL);
    stun_add_flag(&m, STUN_ATTR_USE_CANDIDATE);
    if (stun_add_integrity(&m, pwd, strlen(pwd)) != 0) return -3;
    if (stun_add_fingerprint(&m) != 0) return -4;
    int total = stun_finish(&m);
    if (total <= 0 || !stun_check(buf, (size_t)total)) return -5;
    if (stun_type(buf) != STUN_BINDING_REQUEST || memcmp(stun_txid(buf), txid, 12)) return -6;
    uint16_t ul; const uint8_t *u = stun_find(buf, (size_t)total, STUN_ATTR_USERNAME, &ul);
    if (!u || ul != 9 || memcmp(u, "evtj:h6vY", 9)) return -7;
    if (stun_verify_integrity(buf, (size_t)total, pwd, strlen(pwd)) != 0) return -8;
    if (stun_verify_integrity(buf, (size_t)total, "wrong", 5) == 0) return -9;
    if (stun_verify_fingerprint(buf, (size_t)total) != 0) return -10;
    buf[24] ^= 0xff;
    if (stun_verify_fingerprint(buf, (size_t)total) == 0) return -11;
    buf[24] ^= 0xff;

    stun_addr a4 = { 4, { 192, 0, 2, 1 }, 32853 }, got;
    stun_begin(&m, buf, sizeof buf, STUN_BINDING_SUCCESS, txid);
    stun_add_xor_addr(&m, STUN_ATTR_XOR_MAPPED_ADDRESS, &a4);
    total = stun_finish(&m);
    if (stun_get_xor_addr(buf, (size_t)total, STUN_ATTR_XOR_MAPPED_ADDRESS, &got) != 0) return -12;
    if (got.family != 4 || got.port != 32853 || memcmp(got.addr, a4.addr, 4)) return -13;
    stun_addr a6 = { 6, { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 }, 4500 };
    stun_begin(&m, buf, sizeof buf, STUN_BINDING_SUCCESS, txid);
    stun_add_xor_addr(&m, STUN_ATTR_XOR_MAPPED_ADDRESS, &a6);
    total = stun_finish(&m);
    if (stun_get_xor_addr(buf, (size_t)total, STUN_ATTR_XOR_MAPPED_ADDRESS, &got) != 0) return -14;
    if (got.family != 6 || got.port != 4500 || memcmp(got.addr, a6.addr, 16)) return -15;
    return 0;
}
