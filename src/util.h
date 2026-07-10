#ifndef TRICHAT_UTIL_H
#define TRICHAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

static inline size_t tri_b64enc(const unsigned char *in, size_t n, char *out) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = in[i] << 16;
        if (i + 1 < n) v |= in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < n ? t[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

static inline int tri_b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static inline void tri_hexenc(const uint8_t *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = h[in[i] >> 4]; out[2 * i + 1] = h[in[i] & 15]; }
    out[2 * n] = '\0';
}

static inline int tri_hexdec(const char *in, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int hi = in[2 * i], lo = in[2 * i + 1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0' : (hi | 32) - 'a' + 10;
        lo = (lo >= '0' && lo <= '9') ? lo - '0' : (lo | 32) - 'a' + 10;
        if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

#endif
