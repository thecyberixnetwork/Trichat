#include "srtp.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>

static int aes_cm(Aes *aes, const uint8_t iv[16], const uint8_t *in, uint8_t *out, int len) {
    uint8_t ctr[16], ks[16];
    memcpy(ctr, iv, 16);
    for (int off = 0; off < len; off += 16) {
        if (wc_AesEncryptDirect(aes, ks, ctr) != 0) return -1;
        int n = len - off; if (n > 16) n = 16;
        for (int i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
        uint16_t c = (uint16_t)((ctr[14] << 8) | ctr[15]); c++;
        ctr[14] = (uint8_t)(c >> 8); ctr[15] = (uint8_t)c;
    }
    return 0;
}

static int srtp_kdf(const uint8_t *master_key, const uint8_t master_salt[14], uint8_t label,
                    uint8_t *out, int n) {
    Aes aes; if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_AesSetKeyDirect(&aes, master_key, 16, NULL, AES_ENCRYPTION) == 0) {
        uint8_t iv[16]; memset(iv, 0, sizeof iv);
        memcpy(iv, master_salt, 14);
        iv[7] ^= label;
        uint8_t zeros[64]; memset(zeros, 0, sizeof zeros);
        for (int done = 0; done < n; ) {
            int chunk = n - done; if (chunk > (int)sizeof zeros) chunk = (int)sizeof zeros;
            if (aes_cm(&aes, iv, zeros, out + done, chunk) != 0) { done = -1; break; }

            uint32_t blocks = (uint32_t)((chunk + 15) / 16);
            uint32_t c = (uint32_t)((iv[14] << 8) | iv[15]) + blocks;
            iv[14] = (uint8_t)(c >> 8); iv[15] = (uint8_t)c;
            done += chunk;
        }
        rc = 0;
    }
    wc_AesFree(&aes);
    return rc;
}

int srtp_init(srtp_ctx *c, const uint8_t master_key[16], const uint8_t master_salt[14]) {
    memset(c, 0, sizeof *c);
    uint8_t enckey[16];
    if (srtp_kdf(master_key, master_salt, 0x00, enckey, 16) != 0) return -1;
    if (srtp_kdf(master_key, master_salt, 0x01, c->authkey, 20) != 0) return -1;
    if (srtp_kdf(master_key, master_salt, 0x02, c->salt, 14) != 0) return -1;
    Aes *aes = calloc(1, sizeof(Aes));
    if (!aes || wc_AesInit(aes, NULL, INVALID_DEVID) != 0) { free(aes); return -1; }
    if (wc_AesSetKeyDirect(aes, enckey, 16, NULL, AES_ENCRYPTION) != 0) { wc_AesFree(aes); free(aes); return -1; }
    c->aes = aes;

    uint8_t rtcpenc[16];
    if (srtp_kdf(master_key, master_salt, 0x03, rtcpenc, 16) != 0 ||
        srtp_kdf(master_key, master_salt, 0x04, c->rtcp_authkey, 20) != 0 ||
        srtp_kdf(master_key, master_salt, 0x05, c->rtcp_salt, 14) != 0) { srtp_clear(c); return -1; }
    Aes *aesr = calloc(1, sizeof(Aes));
    if (!aesr || wc_AesInit(aesr, NULL, INVALID_DEVID) != 0) { free(aesr); srtp_clear(c); return -1; }
    if (wc_AesSetKeyDirect(aesr, rtcpenc, 16, NULL, AES_ENCRYPTION) != 0) { wc_AesFree(aesr); free(aesr); srtp_clear(c); return -1; }
    c->aes_rtcp = aesr; c->ready = 1;
    return 0;
}
void srtp_clear(srtp_ctx *c) {
    if (!c) return;
    if (c->aes)      { wc_AesFree((Aes *)c->aes);      free(c->aes);      c->aes = NULL; }
    if (c->aes_rtcp) { wc_AesFree((Aes *)c->aes_rtcp); free(c->aes_rtcp); c->aes_rtcp = NULL; }
    c->ready = 0;
}

static void srtp_iv(const uint8_t salt[14], uint32_t ssrc, uint64_t index, uint8_t iv[16]) {
    memset(iv, 0, 16);
    memcpy(iv, salt, 14);
    iv[4] ^= (uint8_t)(ssrc >> 24); iv[5] ^= (uint8_t)(ssrc >> 16);
    iv[6] ^= (uint8_t)(ssrc >> 8);  iv[7] ^= (uint8_t)ssrc;
    iv[8]  ^= (uint8_t)(index >> 40); iv[9]  ^= (uint8_t)(index >> 32);
    iv[10] ^= (uint8_t)(index >> 24); iv[11] ^= (uint8_t)(index >> 16);
    iv[12] ^= (uint8_t)(index >> 8);  iv[13] ^= (uint8_t)index;
}
static int hmac_sha1(const uint8_t *key, int klen, const uint8_t *d1, int l1,
                     const uint8_t *d2, int l2, uint8_t out[20]) {
    Hmac h; if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_HmacSetKey(&h, WC_SHA, key, (word32)klen) == 0 &&
        wc_HmacUpdate(&h, d1, (word32)l1) == 0 &&
        (l2 == 0 || wc_HmacUpdate(&h, d2, (word32)l2) == 0) &&
        wc_HmacFinal(&h, out) == 0) rc = 0;
    wc_HmacFree(&h);
    return rc;
}

int srtp_rtp_header_len(const uint8_t *pkt, int len) {
    if (len < 12) return len < 0 ? 0 : len;
    int hl = 12 + 4 * (pkt[0] & 0x0F);
    if ((pkt[0] & 0x10) && len >= hl + 4) {
        int words = (pkt[hl + 2] << 8) | pkt[hl + 3];
        hl += 4 + 4 * words;
    }
    return hl <= len ? hl : 12;
}

int srtp_protect(srtp_ctx *c, const uint8_t *rtp, int len, uint8_t *out) {
    if (!c || !c->ready || len < 12 || len + SRTP_AUTH_TAG_LEN > SRTP_MAX_PACKET) return -1;
    int hl = srtp_rtp_header_len(rtp, len);
    uint16_t seq = (uint16_t)((rtp[2] << 8) | rtp[3]);
    uint32_t ssrc = ((uint32_t)rtp[8] << 24) | (rtp[9] << 16) | (rtp[10] << 8) | rtp[11];
    if (c->seq_seen && seq < c->last_seq && (uint16_t)(c->last_seq - seq) < 0x8000) c->roc++;
    c->last_seq = seq; c->seq_seen = 1;
    uint64_t index = ((uint64_t)c->roc << 16) | seq;

    uint8_t iv[16]; srtp_iv(c->salt, ssrc, index, iv);
    memcpy(out, rtp, (size_t)hl);
    if (aes_cm((Aes *)c->aes, iv, rtp + hl, out + hl, len - hl) != 0) return -1;
    uint8_t roc_be[4] = { (uint8_t)(c->roc >> 24), (uint8_t)(c->roc >> 16), (uint8_t)(c->roc >> 8), (uint8_t)c->roc };
    uint8_t tag[20];
    if (hmac_sha1(c->authkey, 20, out, len, roc_be, 4, tag) != 0) return -1;
    memcpy(out + len, tag, SRTP_AUTH_TAG_LEN);
    return len + SRTP_AUTH_TAG_LEN;
}

int srtp_unprotect(srtp_ctx *c, const uint8_t *pkt, int len, uint8_t *out) {
    if (!c || !c->ready || len < 12 + SRTP_AUTH_TAG_LEN) return -1;
    int body = len - SRTP_AUTH_TAG_LEN;
    uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
    uint32_t ssrc = ((uint32_t)pkt[8] << 24) | (pkt[9] << 16) | (pkt[10] << 8) | pkt[11];
    uint32_t roc = c->roc;
    if (c->seq_seen && seq < c->last_seq && (uint16_t)(c->last_seq - seq) < 0x8000) roc++;

    uint8_t roc_be[4] = { (uint8_t)(roc >> 24), (uint8_t)(roc >> 16), (uint8_t)(roc >> 8), (uint8_t)roc };
    uint8_t tag[20];
    if (hmac_sha1(c->authkey, 20, pkt, body, roc_be, 4, tag) != 0) return -1;
    if (memcmp(tag, pkt + body, SRTP_AUTH_TAG_LEN) != 0) return -1;

    uint64_t index = ((uint64_t)roc << 16) | seq;
    int hl = srtp_rtp_header_len(pkt, body);
    uint8_t iv[16]; srtp_iv(c->salt, ssrc, index, iv);
    memcpy(out, pkt, (size_t)hl);
    if (aes_cm((Aes *)c->aes, iv, pkt + hl, out + hl, body - hl) != 0) return -1;
    c->roc = roc; c->last_seq = seq; c->seq_seen = 1;
    return body;
}

int srtcp_unprotect(srtp_ctx *c, const uint8_t *pkt, int len, uint8_t *out) {
    if (!c || !c->ready || !c->aes_rtcp) return -1;
    if (len < 8 + 4 + SRTP_AUTH_TAG_LEN) return -1;
    int body = len - SRTP_AUTH_TAG_LEN;
    uint8_t tag[20];
    if (hmac_sha1(c->rtcp_authkey, 20, pkt, body, NULL, 0, tag) != 0) return -1;
    if (memcmp(tag, pkt + body, SRTP_AUTH_TAG_LEN) != 0) return -1;
    int rtcp_len = body - 4;
    if (rtcp_len < 8) return -1;
    uint32_t eidx = ((uint32_t)pkt[rtcp_len] << 24) | ((uint32_t)pkt[rtcp_len + 1] << 16) |
                    ((uint32_t)pkt[rtcp_len + 2] << 8) | pkt[rtcp_len + 3];
    memcpy(out, pkt, (size_t)rtcp_len);
    if (eidx & 0x80000000u) {
        uint32_t ssrc = ((uint32_t)pkt[4] << 24) | ((uint32_t)pkt[5] << 16) | ((uint32_t)pkt[6] << 8) | pkt[7];
        uint8_t iv[16]; srtp_iv(c->rtcp_salt, ssrc, (uint64_t)(eidx & 0x7fffffff), iv);
        if (aes_cm((Aes *)c->aes_rtcp, iv, pkt + 8, out + 8, rtcp_len - 8) != 0) return -1;
    }
    return rtcp_len;
}

int srtcp_protect(srtp_ctx *c, const uint8_t *rtcp, int rtcp_len, uint8_t *out) {
    if (!c || !c->ready || !c->aes_rtcp || rtcp_len < 8) return -1;
    if (rtcp_len + 4 + SRTP_AUTH_TAG_LEN > SRTP_MAX_PACKET) return -1;
    uint32_t idx = (++c->rtcp_index) & 0x7fffffffu;
    uint32_t ssrc = ((uint32_t)rtcp[4] << 24) | ((uint32_t)rtcp[5] << 16) | ((uint32_t)rtcp[6] << 8) | rtcp[7];
    memcpy(out, rtcp, 8);
    uint8_t iv[16]; srtp_iv(c->rtcp_salt, ssrc, (uint64_t)idx, iv);
    if (aes_cm((Aes *)c->aes_rtcp, iv, rtcp + 8, out + 8, rtcp_len - 8) != 0) return -1;
    uint32_t eidx = 0x80000000u | idx;
    out[rtcp_len]     = (uint8_t)(eidx >> 24); out[rtcp_len + 1] = (uint8_t)(eidx >> 16);
    out[rtcp_len + 2] = (uint8_t)(eidx >> 8);  out[rtcp_len + 3] = (uint8_t)eidx;
    uint8_t tag[20];
    if (hmac_sha1(c->rtcp_authkey, 20, out, rtcp_len + 4, NULL, 0, tag) != 0) return -1;
    memcpy(out + rtcp_len + 4, tag, SRTP_AUTH_TAG_LEN);
    return rtcp_len + 4 + SRTP_AUTH_TAG_LEN;
}

static int hexeq(const uint8_t *got, const char *hex, int n) {
    for (int i = 0; i < n; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        if ((uint8_t)strtol(b, NULL, 16) != got[i]) return 0;
    }
    return 1;
}
int srtp_selftest(void) {
    uint8_t mk[16], ms[14], out[20];
    tri_hexdec("E1F97A0D3E018BE0D64FA32C06DE4139", mk, 16);
    tri_hexdec("0EC675AD498AFEEBB6960B3AABE6", ms, 14);
    if (srtp_kdf(mk, ms, 0x00, out, 16) != 0 || !hexeq(out, "C61E7A93744F39EE10734AFE3FF7A087", 16)) return -1;
    if (srtp_kdf(mk, ms, 0x02, out, 14) != 0 || !hexeq(out, "30CBBC08863D8C85D49DB34A9AE1", 14)) return -2;
    if (srtp_kdf(mk, ms, 0x01, out, 20) != 0 || !hexeq(out, "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4", 20)) return -3;

    uint8_t sk[16], ssalt[14], iv[16], zeros[16] = {0}, ks[16];
    tri_hexdec("2B7E151628AED2A6ABF7158809CF4F3C", sk, 16);
    tri_hexdec("0EC675AD498AFEEBB6960B3AABE6", ssalt, 14);
    srtp_iv(ssalt, 0, 0, iv);
    Aes aes; wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKeyDirect(&aes, sk, 16, NULL, AES_ENCRYPTION);
    int ok = (aes_cm(&aes, iv, zeros, ks, 16) == 0) && hexeq(ks, "681C460B91DE92E2B108D80B0FE1CABB", 16);
    wc_AesFree(&aes);
    if (!ok) return -4;

    srtp_ctx tx, rx;
    if (srtp_init(&tx, mk, ms) != 0 || srtp_init(&rx, mk, ms) != 0) return -5;
    uint8_t rtp[172], prot[200], back[200];
    memset(rtp, 0, sizeof rtp);
    rtp[0] = 0x80; rtp[1] = 111;
    rtp[2] = 0x12; rtp[3] = 0x34;
    rtp[8] = 0xDE; rtp[9] = 0xAD; rtp[10] = 0xBE; rtp[11] = 0xEF;
    for (int i = 12; i < 172; i++) rtp[i] = (uint8_t)(i * 7);
    int pl = srtp_protect(&tx, rtp, 172, prot);
    if (pl != 172 + SRTP_AUTH_TAG_LEN) { srtp_clear(&tx); srtp_clear(&rx); return -6; }
    if (memcmp(prot + 12, rtp + 12, 160) == 0) { srtp_clear(&tx); srtp_clear(&rx); return -7; }
    int rl = srtp_unprotect(&rx, prot, pl, back);
    if (rl != 172 || memcmp(back, rtp, 172) != 0) { srtp_clear(&tx); srtp_clear(&rx); return -8; }
    prot[20] ^= 0x01;
    if (srtp_unprotect(&rx, prot, pl, back) != -1) { srtp_clear(&tx); srtp_clear(&rx); return -9; }
    srtp_clear(&tx); srtp_clear(&rx);

    srtp_ctx tx2, rx2;
    if (srtp_init(&tx2, mk, ms) != 0 || srtp_init(&rx2, mk, ms) != 0) return -10;
    uint8_t ext[172], eprot[200], eback[200];
    memset(ext, 0, sizeof ext);
    ext[0] = 0x90; ext[1] = 111;
    ext[2] = 0x00; ext[3] = 0x01;
    ext[8] = 0xDE; ext[9] = 0xAD; ext[10] = 0xBE; ext[11] = 0xEF;
    ext[12] = 0xBE; ext[13] = 0xDE; ext[14] = 0x00; ext[15] = 0x02;
    if (srtp_rtp_header_len(ext, 172) != 24) { srtp_clear(&tx2); srtp_clear(&rx2); return -11; }
    for (int i = 24; i < 172; i++) ext[i] = (uint8_t)(i * 5);
    int el = srtp_protect(&tx2, ext, 172, eprot);
    if (el != 172 + SRTP_AUTH_TAG_LEN) { srtp_clear(&tx2); srtp_clear(&rx2); return -12; }
    if (memcmp(eprot + 24, ext + 24, 148) == 0) { srtp_clear(&tx2); srtp_clear(&rx2); return -13; }
    if (memcmp(eprot + 12, ext + 12, 12) != 0) { srtp_clear(&tx2); srtp_clear(&rx2); return -14; }
    int erl = srtp_unprotect(&rx2, eprot, el, eback);
    if (erl != 172 || memcmp(eback, ext, 172) != 0) { srtp_clear(&tx2); srtp_clear(&rx2); return -15; }
    srtp_clear(&tx2); srtp_clear(&rx2);

    srtp_ctx cc; if (srtp_init(&cc, mk, ms) != 0) return -16;
    uint8_t rtcp[44], cprot[80], cback[80];
    memset(rtcp, 0, sizeof rtcp);
    rtcp[0] = 0x81; rtcp[1] = 201; rtcp[2] = 0; rtcp[3] = 7;
    rtcp[4] = 0x11; rtcp[5] = 0x22; rtcp[6] = 0x33; rtcp[7] = 0x44;
    for (int i = 8; i < 32; i++) rtcp[i] = (uint8_t)(i * 3);
    rtcp[32] = 0x81; rtcp[33] = 206; rtcp[34] = 0; rtcp[35] = 2;
    rtcp[36] = 0x11; rtcp[37] = 0x22; rtcp[38] = 0x33; rtcp[39] = 0x44;
    rtcp[40] = 0xAA; rtcp[41] = 0xBB; rtcp[42] = 0xCC; rtcp[43] = 0xDD;

    uint8_t civ[16]; uint32_t cssrc = 0x11223344, idx = 5;
    memcpy(cprot, rtcp, 8);
    srtp_iv(cc.rtcp_salt, cssrc, (uint64_t)idx, civ);
    if (aes_cm((Aes *)cc.aes_rtcp, civ, rtcp + 8, cprot + 8, 44 - 8) != 0) { srtp_clear(&cc); return -17; }
    uint32_t eidx = 0x80000000u | idx;
    cprot[44] = (uint8_t)(eidx >> 24); cprot[45] = (uint8_t)(eidx >> 16);
    cprot[46] = (uint8_t)(eidx >> 8);  cprot[47] = (uint8_t)eidx;
    uint8_t ctag[20];
    if (hmac_sha1(cc.rtcp_authkey, 20, cprot, 48, NULL, 0, ctag) != 0) { srtp_clear(&cc); return -18; }
    memcpy(cprot + 48, ctag, SRTP_AUTH_TAG_LEN);
    int cl = 48 + SRTP_AUTH_TAG_LEN;
    if (memcmp(cprot + 8, rtcp + 8, 36) == 0) { srtp_clear(&cc); return -19; }
    int crl = srtcp_unprotect(&cc, cprot, cl, cback);
    if (crl != 44 || memcmp(cback, rtcp, 44) != 0) { srtp_clear(&cc); return -20; }
    cprot[12] ^= 0x01;
    if (srtcp_unprotect(&cc, cprot, cl, cback) != -1) { srtp_clear(&cc); return -21; }

    srtp_ctx pc; if (srtp_init(&pc, mk, ms) != 0) return -22;
    uint8_t pli[12] = { 0x81, 206, 0, 2, 0,0,0,1, 0,0,0,2 };
    uint8_t pprot[80], pback[80];
    int ppl = srtcp_protect(&pc, pli, 12, pprot);
    if (ppl != 12 + 4 + SRTP_AUTH_TAG_LEN) { srtp_clear(&pc); srtp_clear(&cc); return -23; }
    if (srtcp_unprotect(&pc, pprot, ppl, pback) != 12 || memcmp(pback, pli, 12) != 0) { srtp_clear(&pc); srtp_clear(&cc); return -24; }
    srtp_clear(&pc);
    srtp_clear(&cc);
    return 0;
}
