#include "omemo.h"
#include <string.h>
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>

static int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t dlen, uint8_t out[32]) {
    Hmac h;
    if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0) return -1;
    int rc = -1;
    if (wc_HmacSetKey(&h, WC_SHA256, key, (word32)keylen) == 0 &&
        wc_HmacUpdate(&h, data, (word32)dlen) == 0 &&
        wc_HmacFinal(&h, out) == 0) rc = 0;
    wc_HmacFree(&h);
    return rc;
}
static int aes_cbc(int enc, const uint8_t key[32], const uint8_t iv[16],
                   const uint8_t *in, size_t n, uint8_t *out) {
    Aes aes; int rc = -1;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_AesSetKey(&aes, key, 32, iv, enc ? AES_ENCRYPTION : AES_DECRYPTION) == 0 &&
        (enc ? wc_AesCbcEncrypt(&aes, out, in, (word32)n)
             : wc_AesCbcDecrypt(&aes, out, in, (word32)n)) == 0) rc = 0;
    wc_AesFree(&aes);
    return rc;
}

static int kdf_rk(const uint8_t rk[32], const uint8_t dh[32], uint8_t rk_out[32], uint8_t ck_out[32]) {
    uint8_t out[64];
    if (omemo_hkdf(out, 64, dh, 32, rk, 32, (const uint8_t *)"WhisperRatchet", 14) != 0) return -1;
    memcpy(rk_out, out, 32); memcpy(ck_out, out + 32, 32);
    return 0;
}

static int kdf_ck(uint8_t ck[32], uint8_t mk_out[32]) {
    uint8_t one = 0x01, two = 0x02, nck[32];
    if (hmac_sha256(ck, 32, &one, 1, mk_out) != 0) return -1;
    if (hmac_sha256(ck, 32, &two, 1, nck) != 0) return -1;
    memcpy(ck, nck, 32);
    return 0;
}

static int dh_append(uint8_t *buf, size_t *off, const uint8_t priv[32], const uint8_t pub[32]) {
    if (omemo_x25519(buf + *off, priv, pub) != 0) return -1;
    *off += 32;
    return 0;
}

static int x3dh_derive(const uint8_t *secret, size_t slen, uint8_t rk[32], uint8_t ck[32]) {
    uint8_t salt[32] = {0}, out[64];
    if (omemo_hkdf(out, 64, secret, slen, salt, 32, (const uint8_t *)"WhisperText", 11) != 0) return -1;
    memcpy(rk, out, 32); memcpy(ck, out + 32, 32);
    return 0;
}

int omemo_x3dh_init_alice(omemo_session_t *s,
        const uint8_t ik_priv[32], const uint8_t ik_pub[32], const uint8_t ek_priv[32],
        const uint8_t their_ik_pub[32], const uint8_t their_spk_pub[32],
        const uint8_t *their_opk_pub) {
    memset(s, 0, sizeof *s);
    memcpy(s->local_ik, ik_pub, 32); memcpy(s->remote_ik, their_ik_pub, 32);
    uint8_t secret[32 + 4 * 32]; size_t off = 0;
    memset(secret, 0xFF, 32); off = 32;
    if (dh_append(secret, &off, ik_priv, their_spk_pub) != 0) return -1;
    if (dh_append(secret, &off, ek_priv, their_ik_pub) != 0) return -1;
    if (dh_append(secret, &off, ek_priv, their_spk_pub) != 0) return -1;
    if (their_opk_pub && dh_append(secret, &off, ek_priv, their_opk_pub) != 0) return -1;

    uint8_t rk[32], ck[32];
    if (x3dh_derive(secret, off, rk, ck) != 0) return -1;

    memcpy(s->dhr, their_spk_pub, 32); s->have_dhr = 1;
    memcpy(s->ckr, ck, 32);            s->has_ckr = 1;

    if (omemo_x25519_keygen(s->dhs_priv, s->dhs_pub) != 0) return -1;
    uint8_t dh[32];
    if (omemo_x25519(dh, s->dhs_priv, their_spk_pub) != 0) return -1;
    if (kdf_rk(rk, dh, s->root_key, s->cks) != 0) return -1;
    s->has_cks = 1;
    return 0;
}

int omemo_x3dh_init_bob(omemo_session_t *s,
        const uint8_t ik_priv[32], const uint8_t ik_pub[32],
        const uint8_t spk_priv[32], const uint8_t spk_pub[32],
        const uint8_t *opk_priv, const uint8_t their_ik_pub[32], const uint8_t their_ek_pub[32]) {
    memset(s, 0, sizeof *s);
    memcpy(s->local_ik, ik_pub, 32); memcpy(s->remote_ik, their_ik_pub, 32);
    uint8_t secret[32 + 4 * 32]; size_t off = 0;
    memset(secret, 0xFF, 32); off = 32;
    if (dh_append(secret, &off, spk_priv, their_ik_pub) != 0) return -1;
    if (dh_append(secret, &off, ik_priv, their_ek_pub) != 0) return -1;
    if (dh_append(secret, &off, spk_priv, their_ek_pub) != 0) return -1;
    if (opk_priv && dh_append(secret, &off, opk_priv, their_ek_pub) != 0) return -1;

    uint8_t ck[32];
    if (x3dh_derive(secret, off, s->root_key, ck) != 0) return -1;

    memcpy(s->dhs_priv, spk_priv, 32); memcpy(s->dhs_pub, spk_pub, 32);
    memcpy(s->cks, ck, 32); s->has_cks = 1;
    return 0;
}

static int msg_keys(const uint8_t mk[32], uint8_t ck[32], uint8_t mac[32], uint8_t iv[16]) {
    uint8_t salt[32] = {0}, out[80];
    if (omemo_hkdf(out, 80, mk, 32, salt, 32, (const uint8_t *)"WhisperMessageKeys", 18) != 0) return -1;
    memcpy(ck, out, 32); memcpy(mac, out + 32, 32); memcpy(iv, out + 64, 16);
    return 0;
}

static int whisper_mac(const uint8_t mackey[32], const uint8_t sender_ik[32], const uint8_t recv_ik[32],
                       const uint8_t *serialized, size_t slen, uint8_t mac8[8]) {
    uint8_t si[33], ri[33]; si[0] = ri[0] = OMEMO_DJB_TYPE;
    memcpy(si + 1, sender_ik, 32); memcpy(ri + 1, recv_ik, 32);
    uint8_t full[32];
    Hmac hm; if (wc_HmacInit(&hm, NULL, INVALID_DEVID) != 0) return -1;
    int ok = (wc_HmacSetKey(&hm, WC_SHA256, mackey, 32) == 0 &&
              wc_HmacUpdate(&hm, si, 33) == 0 && wc_HmacUpdate(&hm, ri, 33) == 0 &&
              wc_HmacUpdate(&hm, serialized, (word32)slen) == 0 &&
              wc_HmacFinal(&hm, full) == 0);
    wc_HmacFree(&hm);
    if (!ok) return -1;
    memcpy(mac8, full, 8);
    return 0;
}

static int body_encrypt(const uint8_t mk[32], const uint8_t sender_ik[32], const uint8_t recv_ik[32],
                        const uint8_t ratchet_pub[32], uint32_t counter, uint32_t pn,
                        const uint8_t *pt, size_t ptlen, uint8_t *out, size_t outcap) {
    uint8_t ckey[32], mackey[32], iv[16];
    if (msg_keys(mk, ckey, mackey, iv) != 0) return -1;
    size_t pad = 16 - (ptlen % 16); if (pad == 0) pad = 16;
    size_t clen = ptlen + pad;
    uint8_t buf[OMEMO_MAX_CIPHERTEXT]; if (clen > sizeof buf) return -1;
    memcpy(buf, pt, ptlen); memset(buf + ptlen, (uint8_t)pad, pad);
    uint8_t ct[OMEMO_MAX_CIPHERTEXT];
    if (aes_cbc(1, ckey, iv, buf, clen, ct) != 0) return -1;
    int slen = omemo_signal_serialize(out, outcap - 8, ratchet_pub, counter, pn, ct, clen);
    if (slen < 0) return -1;
    uint8_t mac8[8];
    if (whisper_mac(mackey, sender_ik, recv_ik, out, (size_t)slen, mac8) != 0) return -1;
    memcpy(out + slen, mac8, 8);
    return slen + 8;
}

static int body_decrypt(const uint8_t mk[32], const uint8_t sender_ik[32], const uint8_t recv_ik[32],
                        const uint8_t *serialized, size_t slen, const uint8_t *ct, size_t ctlen,
                        uint8_t *pt, size_t ptcap) {
    if (ctlen < 16 || ctlen % 16 != 0) return -1;
    uint8_t ckey[32], mackey[32], iv[16];
    if (msg_keys(mk, ckey, mackey, iv) != 0) return -1;
    uint8_t mac8[8];
    if (whisper_mac(mackey, sender_ik, recv_ik, serialized, slen, mac8) != 0) return -1;
    uint8_t diff = 0; for (int i = 0; i < 8; i++) diff |= (uint8_t)(mac8[i] ^ serialized[slen + i]);
    if (diff) return -1;
    uint8_t buf[OMEMO_MAX_CIPHERTEXT]; if (ctlen > sizeof buf) return -1;
    if (aes_cbc(0, ckey, iv, ct, ctlen, buf) != 0) return -1;
    uint8_t pad = buf[ctlen - 1];
    if (pad == 0 || pad > 16 || pad > ctlen) return -1;
    for (size_t i = 0; i < pad; i++) if (buf[ctlen - 1 - i] != pad) return -1;
    size_t ptlen = ctlen - pad;
    if (ptlen > ptcap) return -1;
    memcpy(pt, buf, ptlen);
    return (int)ptlen;
}

static int skip_message_keys(omemo_session_t *s, uint32_t until) {
    if (!s->has_ckr) return 0;
    while (s->nr < until) {
        if (s->nskip >= OMEMO_MAX_SKIP) return -1;
        uint8_t mk[32];
        if (kdf_ck(s->ckr, mk) != 0) return -1;
        memcpy(s->skipped[s->nskip].dhr, s->dhr, 32);
        s->skipped[s->nskip].n = s->nr;
        memcpy(s->skipped[s->nskip].mk, mk, 32);
        s->nskip++;
        s->nr++;
    }
    return 0;
}
static int dh_ratchet(omemo_session_t *s, const uint8_t dh_pub[32]) {
    s->pn = s->ns; s->ns = 0; s->nr = 0;
    memcpy(s->dhr, dh_pub, 32); s->have_dhr = 1;
    uint8_t dh[32];
    if (omemo_x25519(dh, s->dhs_priv, s->dhr) != 0) return -1;
    if (kdf_rk(s->root_key, dh, s->root_key, s->ckr) != 0) return -1;
    s->has_ckr = 1;
    if (omemo_x25519_keygen(s->dhs_priv, s->dhs_pub) != 0) return -1;
    if (omemo_x25519(dh, s->dhs_priv, s->dhr) != 0) return -1;
    if (kdf_rk(s->root_key, dh, s->root_key, s->cks) != 0) return -1;
    s->has_cks = 1;
    return 0;
}

int omemo_ratchet_encrypt(omemo_session_t *s, const uint8_t *pt, size_t ptlen,
        uint8_t *out, size_t outcap) {
    if (!s->has_cks) return -1;
    uint8_t mk[32];
    if (kdf_ck(s->cks, mk) != 0) return -1;
    uint32_t counter = s->ns, pn = s->pn;
    s->ns++;
    return body_encrypt(mk, s->local_ik, s->remote_ik, s->dhs_pub, counter, pn, pt, ptlen, out, outcap);
}

int omemo_ratchet_decrypt(omemo_session_t *s, const uint8_t *wire, size_t wirelen,
        uint8_t *pt, size_t ptcap) {
    if (wirelen < 8) return -1;
    size_t slen = wirelen - 8;
    uint8_t dh_pub[32]; uint32_t counter, pn; const uint8_t *ct; size_t ctlen;
    if (omemo_signal_parse(wire, slen, dh_pub, &counter, &pn, &ct, &ctlen) != 0) return -1;

    for (int i = 0; i < s->nskip; i++) {
        if (s->skipped[i].n == counter && memcmp(s->skipped[i].dhr, dh_pub, 32) == 0) {
            int r = body_decrypt(s->skipped[i].mk, s->remote_ik, s->local_ik, wire, slen, ct, ctlen, pt, ptcap);
            if (r < 0) return -1;
            s->skipped[i] = s->skipped[--s->nskip];
            return r;
        }
    }

    if (!s->have_dhr || memcmp(dh_pub, s->dhr, 32) != 0) {
        if (skip_message_keys(s, pn) != 0) return -1;
        if (dh_ratchet(s, dh_pub) != 0) return -1;
    }

    if (skip_message_keys(s, counter) != 0) return -1;
    uint8_t mk[32];
    if (kdf_ck(s->ckr, mk) != 0) return -1;
    s->nr++;
    return body_decrypt(mk, s->remote_ik, s->local_ik, wire, slen, ct, ctlen, pt, ptcap);
}

static int exchange(omemo_session_t *from, omemo_session_t *to, const char *text) {
    uint8_t wire[512], pt[256];
    int cl = omemo_ratchet_encrypt(from, (const uint8_t *)text, strlen(text), wire, sizeof wire);
    if (cl < 0) return -1;
    int pl = omemo_ratchet_decrypt(to, wire, (size_t)cl, pt, sizeof pt);
    if (pl < 0 || (size_t)pl != strlen(text) || memcmp(pt, text, pl) != 0) return -1;
    return 0;
}

int omemo_session_selftest(void) {
    uint8_t bob_ik_p[32], bob_ik_P[32], bob_spk_p[32], bob_spk_P[32], bob_opk_p[32], bob_opk_P[32];
    uint8_t al_ik_p[32], al_ik_P[32], al_ek_p[32], al_ek_P[32];
    if (omemo_x25519_keygen(bob_ik_p, bob_ik_P) || omemo_x25519_keygen(bob_spk_p, bob_spk_P) ||
        omemo_x25519_keygen(bob_opk_p, bob_opk_P) || omemo_x25519_keygen(al_ik_p, al_ik_P) ||
        omemo_x25519_keygen(al_ek_p, al_ek_P)) return -1;

    omemo_session_t alice, bob;
    if (omemo_x3dh_init_alice(&alice, al_ik_p, al_ik_P, al_ek_p, bob_ik_P, bob_spk_P, bob_opk_P) != 0) {
        fprintf(stderr, "omemo session: alice x3dh failed\n"); return -1; }
    if (omemo_x3dh_init_bob(&bob, bob_ik_p, bob_ik_P, bob_spk_p, bob_spk_P, bob_opk_p, al_ik_P, al_ek_P) != 0) {
        fprintf(stderr, "omemo session: bob x3dh failed\n"); return -1; }

    if (exchange(&alice, &bob, "hello bob, this is the first OMEMO message") != 0) {
        fprintf(stderr, "omemo session: A->B msg1 failed\n"); return -1; }

    if (exchange(&bob, &alice, "hi alice, got it") != 0) {
        fprintf(stderr, "omemo session: B->A reply failed\n"); return -1; }

    if (exchange(&alice, &bob, "message two") != 0 || exchange(&alice, &bob, "message three") != 0 ||
        exchange(&bob, &alice, "ack two and three") != 0) {
        fprintf(stderr, "omemo session: streaming failed\n"); return -1; }

    {
        uint8_t wA[512], wB[512], out[256];
        const char *mA = "out-of-order A", *mB = "out-of-order B";
        int cA = omemo_ratchet_encrypt(&alice, (const uint8_t *)mA, strlen(mA), wA, sizeof wA);
        int cB = omemo_ratchet_encrypt(&alice, (const uint8_t *)mB, strlen(mB), wB, sizeof wB);
        if (cA < 0 || cB < 0) return -1;
        int p = omemo_ratchet_decrypt(&bob, wB, (size_t)cB, out, sizeof out);
        if (p < 0 || memcmp(out, mB, p) != 0) { fprintf(stderr, "omemo session: OOO B failed\n"); return -1; }
        p = omemo_ratchet_decrypt(&bob, wA, (size_t)cA, out, sizeof out);
        if (p < 0 || memcmp(out, mA, p) != 0) { fprintf(stderr, "omemo session: OOO A (skipped) failed\n"); return -1; }
    }

    {
        uint8_t wire[512], out[256];
        int cl = omemo_ratchet_encrypt(&alice, (const uint8_t *)"tamper me", 9, wire, sizeof wire);
        if (cl < 0) return -1;
        wire[cl - 12] ^= 0x40;
        if (omemo_ratchet_decrypt(&bob, wire, (size_t)cl, out, sizeof out) >= 0) {
            fprintf(stderr, "omemo session: forged ciphertext accepted\n"); return -1; }
    }

    {
        omemo_session_t a2, b2;
        if (omemo_x3dh_init_alice(&a2, al_ik_p, al_ik_P, al_ek_p, bob_ik_P, bob_spk_P, NULL) != 0) return -1;
        if (omemo_x3dh_init_bob(&b2, bob_ik_p, bob_ik_P, bob_spk_p, bob_spk_P, NULL, al_ik_P, al_ek_P) != 0) return -1;
        if (exchange(&a2, &b2, "no-opk session works") != 0) {
            fprintf(stderr, "omemo session: no-OPK failed\n"); return -1; }
    }
    return 0;
}
