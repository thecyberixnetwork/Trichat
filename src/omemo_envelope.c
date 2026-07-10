#include "omemo.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

static void djb_b64enc(const uint8_t key[OMEMO_KEY_LEN], char *out) {
    uint8_t d[1 + OMEMO_KEY_LEN]; d[0] = OMEMO_DJB_TYPE; memcpy(d + 1, key, OMEMO_KEY_LEN);
    tri_b64enc(d, sizeof d, out);
}

static int b64dec(const char *in, size_t inlen, uint8_t *out, size_t cap) {
    int bits = 0, acc = 0; size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i];
        if (c == '=' ) break;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = tri_b64val(c); if (v < 0) return -1;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; if (o >= cap) return -1; out[o++] = (uint8_t)((acc >> bits) & 0xff); }
    }
    return (int)o;
}

static int gcm128(int enc, const uint8_t key[OMEMO_GCM_KEYLEN], const uint8_t *iv, int ivlen,
                  const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[OMEMO_TAG_LEN]) {
    Aes aes; int rc = -1;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_AesGcmSetKey(&aes, key, OMEMO_GCM_KEYLEN) == 0) {
        if (enc) rc = wc_AesGcmEncrypt(&aes, out, in, (word32)n, iv, (word32)ivlen, tag, OMEMO_TAG_LEN, NULL, 0) == 0 ? 0 : -1;
        else     rc = wc_AesGcmDecrypt(&aes, out, in, (word32)n, iv, (word32)ivlen, tag, OMEMO_TAG_LEN, NULL, 0) == 0 ? 0 : -1;
    }
    wc_AesFree(&aes);
    return rc;
}

static const char *elem_open(const char *xml, const char *tag) {
    char needle[48]; snprintf(needle, sizeof needle, "<%s", tag);
    size_t nl = strlen(needle);
    for (const char *p = xml; (p = strstr(p, needle)); p += nl) {
        char d = p[nl];
        if (d == ' ' || d == '>' || d == '/' || d == '\t' || d == '\n') {
            const char *gt = strchr(p, '>'); return gt ? gt + 1 : NULL;
        }
    }
    return NULL;
}

static int elem_text(const char *xml, const char *tag, char *out, size_t cap) {
    const char *s = elem_open(xml, tag); if (!s) return -1;
    char close[48]; snprintf(close, sizeof close, "</%s>", tag);
    const char *e = strstr(s, close); if (!e) return -1;
    size_t n = (size_t)(e - s); if (n >= cap) return -1;
    memcpy(out, s, n); out[n] = '\0';
    return 0;
}

static long attr_num(const char *elem_start, const char *name) {
    char needle[32]; snprintf(needle, sizeof needle, "%s=", name);
    const char *q = strstr(elem_start, needle);
    if (!q) return -1;
    q += strlen(needle);
    if (*q == '"' || *q == '\'') q++;
    return strtol(q, NULL, 10);
}

int omemo_payload_encrypt(const uint8_t *pt, size_t ptlen,
        uint8_t keydata[OMEMO_KEYDATA_LEN], uint8_t iv[OMEMO_IV_LEN],
        uint8_t *payload, size_t paycap, int *paylen) {
    if (ptlen > paycap) return -1;
    uint8_t key[OMEMO_GCM_KEYLEN], tag[OMEMO_TAG_LEN];
    if (omemo_random(key, sizeof key) != 0 || omemo_random(iv, OMEMO_IV_LEN) != 0) return -1;
    if (gcm128(1, key, iv, OMEMO_IV_LEN, pt, ptlen, payload, tag) != 0) return -1;
    memcpy(keydata, key, OMEMO_GCM_KEYLEN); memcpy(keydata + OMEMO_GCM_KEYLEN, tag, OMEMO_TAG_LEN);
    *paylen = (int)ptlen;
    return 0;
}
int omemo_payload_decrypt(const uint8_t keydata[OMEMO_KEYDATA_LEN], const uint8_t *iv, int ivlen,
        const uint8_t *payload, int paylen, uint8_t *pt, size_t ptcap) {
    if (paylen < 0 || (size_t)paylen > ptcap) return -1;

    if (gcm128(0, keydata, iv, ivlen, payload, (size_t)paylen, pt, (uint8_t *)keydata + OMEMO_GCM_KEYLEN) != 0) return -1;
    return paylen;
}

int omemo_envelope_build(uint32_t sender_device_id, const omemo_keyslot_t *slots, int nslots,
        const uint8_t iv[OMEMO_IV_LEN], const uint8_t *payload, int paylen, char *out, size_t outcap) {
    if (nslots < 1) return -1;
    size_t o = 0;
    int w = snprintf(out + o, outcap - o, "<encrypted xmlns='%s'><header sid='%u'>", OMEMO_NS, sender_device_id);
    if (w < 0 || (size_t)w >= outcap - o) return -1; o += w;
    for (int i = 0; i < nslots; i++) {
        char b64[1400];
        if ((size_t)slots[i].keyblob_len > (sizeof b64 * 3) / 4) return -1;
        tri_b64enc(slots[i].keyblob, (size_t)slots[i].keyblob_len, b64);
        w = snprintf(out + o, outcap - o, "<key rid='%u'%s>%s</key>",
                     slots[i].device_id, slots[i].is_prekey ? " prekey='true'" : "", b64);
        if (w < 0 || (size_t)w >= outcap - o) return -1; o += w;
    }
    char ivb64[32]; tri_b64enc(iv, OMEMO_IV_LEN, ivb64);
    char *payb64 = malloc(((size_t)paylen / 3 + 1) * 4 + 8); if (!payb64) return -1;
    tri_b64enc(payload, (size_t)paylen, payb64);
    w = snprintf(out + o, outcap - o, "<iv>%s</iv></header><payload>%s</payload></encrypted>", ivb64, payb64);
    free(payb64);
    if (w < 0 || (size_t)w >= outcap - o) return -1;
    return 0;
}
int omemo_envelope_parse(const char *xml, uint32_t my_device_id, uint32_t *sender_sid,
        uint8_t *keyblob, size_t keyblobcap, int *keyblob_len, int *is_prekey,
        uint8_t iv[OMEMO_IV_MAX], int *ivlen, uint8_t *payload, size_t paycap, int *paylen) {
    const char *hdr = strstr(xml, "<header");
    if (sender_sid) *sender_sid = hdr ? (uint32_t)attr_num(hdr, "sid") : 0;

    const char *found = NULL, *found_gt = NULL;
    for (const char *p = xml; (p = strstr(p, "<key")); p += 4) {
        char d = p[4]; if (d != ' ' && d != '\t') continue;
        const char *gt = strchr(p, '>'); if (!gt) break;
        if (attr_num(p, "rid") != (long)my_device_id) continue;
        found = p; found_gt = gt; break;
    }
    if (!found) return 0;
    *is_prekey = 0;
    { const char *q = strstr(found, "prekey="); if (q && q < found_gt) { q += 7; if (*q == '\'' || *q == '"') q++;
        *is_prekey = (*q == 't' || *q == 'T' || *q == '1'); } }
    const char *e = strstr(found_gt + 1, "</key>"); if (!e) return -1;
    char kb64[1400]; size_t n = (size_t)(e - (found_gt + 1)); if (n >= sizeof kb64) return -1;
    memcpy(kb64, found_gt + 1, n); kb64[n] = '\0';
    int kl = b64dec(kb64, strlen(kb64), keyblob, keyblobcap);
    if (kl < 0) return -1; *keyblob_len = kl;

    char ivb64[64], *payb64 = malloc(paycap * 2 + 16); if (!payb64) return -1;
    if (elem_text(xml, "iv", ivb64, sizeof ivb64) != 0) { free(payb64); return -1; }
    if (elem_text(xml, "payload", payb64, paycap * 2 + 16) != 0) { free(payb64); return -1; }
    int il = b64dec(ivb64, strlen(ivb64), iv, OMEMO_IV_MAX);
    if (il != 12 && il != 16) { free(payb64); return -1; }
    *ivlen = il;
    int pl = b64dec(payb64, strlen(payb64), payload, paycap);
    free(payb64);
    if (pl < 0) return -1; *paylen = pl;
    return 1;
}

int omemo_envelope_encrypt(uint32_t sender_device_id, const omemo_recipient_t *rcpts, int nrcpts,
        const uint8_t *pt, size_t ptlen, char *out, size_t outcap) {
    if (nrcpts < 1 || nrcpts > 16 || ptlen > 1024) return -1;
    uint8_t keydata[OMEMO_KEYDATA_LEN], iv[OMEMO_IV_LEN], payload[1024]; int paylen;
    if (omemo_payload_encrypt(pt, ptlen, keydata, iv, payload, sizeof payload, &paylen) != 0) return -1;
    uint8_t wires[16][512]; omemo_keyslot_t slots[16];
    for (int i = 0; i < nrcpts; i++) {
        int wl = omemo_ratchet_encrypt(rcpts[i].session, keydata, sizeof keydata, wires[i], sizeof wires[i]);
        if (wl < 0) return -1;
        slots[i].device_id = rcpts[i].device_id; slots[i].keyblob = wires[i]; slots[i].keyblob_len = wl; slots[i].is_prekey = 0;
    }
    return omemo_envelope_build(sender_device_id, slots, nrcpts, iv, payload, paylen, out, outcap);
}
int omemo_envelope_decrypt(const char *xml, uint32_t my_device_id, omemo_session_t *session,
        uint8_t *pt, size_t ptcap) {
    uint32_t sid; uint8_t keyblob[512], iv[OMEMO_IV_MAX], payload[1024]; int kbl, isp, ivlen, paylen;
    int r = omemo_envelope_parse(xml, my_device_id, &sid, keyblob, sizeof keyblob, &kbl, &isp, iv, &ivlen, payload, sizeof payload, &paylen);
    if (r <= 0) return -1;
    uint8_t keydata[64];
    int kl = omemo_ratchet_decrypt(session, keyblob, (size_t)kbl, keydata, sizeof keydata);
    if (kl != OMEMO_KEYDATA_LEN) return -1;
    return omemo_payload_decrypt(keydata, iv, ivlen, payload, paylen, pt, ptcap);
}

int omemo_devicelist_build(const uint32_t *ids, int n, char *out, size_t outcap) {
    size_t o = 0;
    int w = snprintf(out + o, outcap - o, "<list xmlns='%s'>", OMEMO_NS);
    if (w < 0 || (size_t)w >= outcap - o) return -1; o += w;
    for (int i = 0; i < n; i++) {
        w = snprintf(out + o, outcap - o, "<device id='%u'/>", ids[i]);
        if (w < 0 || (size_t)w >= outcap - o) return -1; o += w;
    }
    w = snprintf(out + o, outcap - o, "</list>");
    if (w < 0 || (size_t)w >= outcap - o) return -1;
    return 0;
}
int omemo_devicelist_parse(const char *xml, uint32_t *ids, int cap) {
    int n = 0;
    for (const char *p = xml; (p = strstr(p, "<device")); p += 7) {
        char d = p[7]; if (d != ' ' && d != '\t') continue;
        long id = attr_num(p, "id"); if (id < 0) continue;
        if (n >= cap) return -1;
        ids[n++] = (uint32_t)id;
    }
    return n;
}

int omemo_bundle_build(const omemo_bundle_t *b, char *out, size_t outcap) {
    char ik[64], spk[64], sig[128];
    djb_b64enc(b->ik_pub, ik);
    djb_b64enc(b->spk_pub, spk);
    tri_b64enc(b->spk_sig, OMEMO_SIG_LEN, sig);
    size_t o = 0;
    int w = snprintf(out + o, outcap - o,
        "<bundle xmlns='%s'><signedPreKeyPublic signedPreKeyId='%u'>%s</signedPreKeyPublic>"
        "<signedPreKeySignature>%s</signedPreKeySignature><identityKey>%s</identityKey><prekeys>",
        OMEMO_NS, b->signed_prekey_id, spk, sig, ik);
    if (w < 0 || (size_t)w >= outcap - o) return -1; o += w;
    for (int i = 0; i < b->nprekeys; i++) {
        char pk[64]; djb_b64enc(b->prekey_pubs[i], pk);
        w = snprintf(out + o, outcap - o, "<preKeyPublic preKeyId='%u'>%s</preKeyPublic>", b->prekey_ids[i], pk);
        if (w < 0 || (size_t)w >= outcap - o) return -1; o += w;
    }
    w = snprintf(out + o, outcap - o, "</prekeys></bundle>");
    if (w < 0 || (size_t)w >= outcap - o) return -1;
    return 0;
}

static int djb_b64dec(const char *b64, uint8_t key[OMEMO_KEY_LEN]) {
    uint8_t d[1 + OMEMO_KEY_LEN + 1];
    int n = b64dec(b64, strlen(b64), d, sizeof d);
    if (n != 1 + OMEMO_KEY_LEN || d[0] != OMEMO_DJB_TYPE) return -1;
    memcpy(key, d + 1, OMEMO_KEY_LEN);
    return 0;
}
int omemo_bundle_parse(const char *xml, omemo_bundle_t *b) {
    memset(b, 0, sizeof *b);
    char tmp[128];
    const char *spk_open = elem_open(xml, "signedPreKeyPublic"); if (!spk_open) return -1;

    { const char *lt = spk_open; while (lt > xml && *lt != '<') lt--;
      long id = attr_num(lt, "signedPreKeyId"); if (id < 0) return -1; b->signed_prekey_id = (uint32_t)id; }
    if (elem_text(xml, "signedPreKeyPublic", tmp, sizeof tmp) != 0 || djb_b64dec(tmp, b->spk_pub) != 0) return -1;
    if (elem_text(xml, "signedPreKeySignature", tmp, sizeof tmp) != 0 ||
        b64dec(tmp, strlen(tmp), b->spk_sig, OMEMO_SIG_LEN) != OMEMO_SIG_LEN) return -1;
    if (elem_text(xml, "identityKey", tmp, sizeof tmp) != 0 || djb_b64dec(tmp, b->ik_pub) != 0) return -1;
    for (const char *p = xml; (p = strstr(p, "<preKeyPublic")); p += 13) {
        char d = p[13]; if (d != ' ' && d != '\t') continue;
        long id = attr_num(p, "preKeyId"); if (id < 0) continue;
        const char *gt = strchr(p, '>'); if (!gt) break;
        const char *e = strstr(gt + 1, "</preKeyPublic>"); if (!e) return -1;
        size_t n = (size_t)(e - (gt + 1)); if (n >= sizeof tmp) return -1;
        memcpy(tmp, gt + 1, n); tmp[n] = '\0';
        if (b->nprekeys >= (int)(sizeof b->prekey_ids / sizeof b->prekey_ids[0])) break;
        if (djb_b64dec(tmp, b->prekey_pubs[b->nprekeys]) != 0) return -1;
        b->prekey_ids[b->nprekeys++] = (uint32_t)id;
    }
    return 0;
}

int omemo_envelope_selftest(void) {
    uint8_t bik_p[32], bik_P[32], bspk_p[32], bspk_P[32], bopk_p[32], bopk_P[32];
    uint8_t aik_p[32], aik_P[32], aek_p[32], aek_P[32];
    if (omemo_x25519_keygen(bik_p, bik_P) || omemo_x25519_keygen(bspk_p, bspk_P) ||
        omemo_x25519_keygen(bopk_p, bopk_P) || omemo_x25519_keygen(aik_p, aik_P) ||
        omemo_x25519_keygen(aek_p, aek_P)) return -1;
    omemo_session_t alice, bob;
    if (omemo_x3dh_init_alice(&alice, aik_p, aik_P, aek_p, bik_P, bspk_P, bopk_P) != 0) return -1;
    if (omemo_x3dh_init_bob(&bob, bik_p, bik_P, bspk_p, bspk_P, bopk_p, aik_P, aek_P) != 0) return -1;

    const uint32_t ALICE_DEV = 0x22221111u, BOB_DEV = 0x0000abcdu;
    const char *msg = "the eagle lands at midnight \xF0\x9F\xA6\x85";
    char xml[4096];
    omemo_recipient_t r = { BOB_DEV, &alice };
    if (omemo_envelope_encrypt(ALICE_DEV, &r, 1, (const uint8_t *)msg, strlen(msg), xml, sizeof xml) != 0) {
        fprintf(stderr, "envelope: encrypt failed\n"); return -1; }
    uint8_t out[256];
    int pl = omemo_envelope_decrypt(xml, BOB_DEV, &bob, out, sizeof out);
    if (pl < 0 || (size_t)pl != strlen(msg) || memcmp(out, msg, pl) != 0) {
        fprintf(stderr, "envelope: round-trip failed\n"); return -1; }

    if (omemo_envelope_decrypt(xml, 0xDEADBEEFu, &bob, out, sizeof out) >= 0) {
        fprintf(stderr, "envelope: decrypted for a foreign device\n"); return -1; }

    {
        char bad[4096]; snprintf(bad, sizeof bad, "%s", xml);
        char *pay = strstr(bad, "<payload>"); if (pay) { pay[9] = (pay[9] == 'A') ? 'B' : 'A'; }
        omemo_session_t bob2;
        omemo_x3dh_init_bob(&bob2, bik_p, bik_P, bspk_p, bspk_P, bopk_p, aik_P, aek_P);
        if (omemo_envelope_decrypt(bad, BOB_DEV, &bob2, out, sizeof out) >= 0) {
            fprintf(stderr, "envelope: accepted a tampered payload\n"); return -1; }
    }

    {
        uint32_t ids[3] = { 0x11111111u, 0x22u, 0xfffffffeu }, got[8];
        char dl[256];
        if (omemo_devicelist_build(ids, 3, dl, sizeof dl) != 0) return -1;
        int n = omemo_devicelist_parse(dl, got, 8);
        if (n != 3 || got[0] != ids[0] || got[1] != ids[1] || got[2] != ids[2]) {
            fprintf(stderr, "envelope: devicelist round-trip failed\n"); return -1; }
    }

    {
        omemo_bundle_t b, b2; memset(&b, 0, sizeof b);
        memcpy(b.ik_pub, aik_P, 32);
        uint8_t sp_priv[32];
        if (omemo_x25519_keygen(sp_priv, b.spk_pub) != 0) return -1;
        b.signed_prekey_id = 5;
        if (omemo_xeddsa_sign(b.spk_sig, aik_p, b.spk_pub, 32) != 0) return -1;
        for (int i = 0; i < 4; i++) { uint8_t pkp[32]; if (omemo_x25519_keygen(pkp, b.prekey_pubs[i]) != 0) return -1; b.prekey_ids[i] = (uint32_t)(100 + i); }
        b.nprekeys = 4;
        char xb[4096];
        if (omemo_bundle_build(&b, xb, sizeof xb) != 0) return -1;
        if (omemo_bundle_parse(xb, &b2) != 0) { fprintf(stderr, "envelope: bundle parse failed\n"); return -1; }
        if (b2.signed_prekey_id != 5 || b2.nprekeys != 4 ||
            memcmp(b2.ik_pub, b.ik_pub, 32) || memcmp(b2.spk_pub, b.spk_pub, 32) ||
            memcmp(b2.spk_sig, b.spk_sig, 64) || b2.prekey_ids[3] != 103 ||
            memcmp(b2.prekey_pubs[2], b.prekey_pubs[2], 32)) {
            fprintf(stderr, "envelope: bundle round-trip mismatch\n"); return -1; }

        if (omemo_xeddsa_verify(b2.spk_sig, b2.ik_pub, b2.spk_pub, 32) != 0) {
            fprintf(stderr, "envelope: bundle SPK signature did not verify\n"); return -1; }
    }
    return 0;
}
