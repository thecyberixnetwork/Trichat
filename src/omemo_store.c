#include "omemo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define STORE_MAGIC   0x4f4d5301u
#define N_ONETIME     60
#define MAX_SESSIONS  32

struct omemo_store {
    char path[512];
    int  dirty;
    struct persist {
        uint32_t magic, version;
        omemo_identity_t id;
        uint32_t spk_id; uint8_t spk_priv[32], spk_pub[32], spk_sig[64];
        int nopk;
        struct { uint32_t id; uint8_t priv[32], pub[32]; uint8_t used; } opk[N_ONETIME];
        int nsessions;
        struct { char bare[128]; uint32_t device_id; omemo_session_t sess; signed char trust; } sess[MAX_SESSIONS];
    } d;
};

static void mkdir_p(const char *path) {
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    mkdir(tmp, 0700);
}
static void store_path(const char *acct_key, char *out, size_t cap) {
    const char *home = getenv("HOME"); if (!home) home = ".";
    char dir[512]; snprintf(dir, sizeof dir, "%s/.config/trichat/omemo", home);
    mkdir_p(dir);
    char safe[128]; snprintf(safe, sizeof safe, "%s", acct_key);
    for (char *p = safe; *p; p++) if (*p == '/' || *p == ':') *p = '_';
    snprintf(out, cap, "%s/%s.store", dir, safe);
}
static int store_save(omemo_store_t *s) {
    FILE *f = fopen(s->path, "wb"); if (!f) return -1;
    size_t w = fwrite(&s->d, sizeof s->d, 1, f);
    fclose(f);
    if (w == 1) chmod(s->path, 0600);
    return w == 1 ? 0 : -1;
}

static int sign_spk(const uint8_t ik_priv[32], const uint8_t spk_pub[32], uint8_t sig[64]) {
    uint8_t djb[33]; djb[0] = OMEMO_DJB_TYPE; memcpy(djb + 1, spk_pub, 32);
    return omemo_xeddsa_sign(sig, ik_priv, djb, sizeof djb);
}
static int generate(struct persist *d) {
    memset(d, 0, sizeof *d);
    d->magic = STORE_MAGIC; d->version = 1;
    if (omemo_identity_generate(&d->id) != 0) return -1;
    d->spk_id = 1;
    if (omemo_x25519_keygen(d->spk_priv, d->spk_pub) != 0) return -1;
    if (sign_spk(d->id.ik_priv, d->spk_pub, d->spk_sig) != 0) return -1;
    for (int i = 0; i < N_ONETIME; i++) {
        d->opk[i].id = (uint32_t)(i + 1);
        if (omemo_x25519_keygen(d->opk[i].priv, d->opk[i].pub) != 0) return -1;
    }
    d->nopk = N_ONETIME;
    return 0;
}

omemo_store_t *omemo_store_open(const char *acct_key) {
    omemo_store_t *s = calloc(1, sizeof *s); if (!s) return NULL;
    store_path(acct_key, s->path, sizeof s->path);
    FILE *f = fopen(s->path, "rb");
    if (f) {
        size_t r = fread(&s->d, sizeof s->d, 1, f); fclose(f);
        if (r == 1 && s->d.magic == STORE_MAGIC) return s;
    }
    if (generate(&s->d) != 0) { free(s); return NULL; }
    if (store_save(s) != 0) { free(s); return NULL; }
    return s;
}
void omemo_store_flush(omemo_store_t *s) { if (s && s->dirty && store_save(s) == 0) s->dirty = 0; }
void omemo_store_close(omemo_store_t *s) { if (!s) return; omemo_store_flush(s); free(s); }
uint32_t omemo_store_device_id(const omemo_store_t *s) { return s->d.id.device_id; }

int omemo_store_fingerprint(omemo_store_t *s, char *out, size_t outcap) {
    if (outcap < 2 * 32 + 1) return -1;
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = hex[s->d.id.ik_pub[i] >> 4]; out[2 * i + 1] = hex[s->d.id.ik_pub[i] & 15]; }
    out[64] = '\0';
    return 0;
}

int omemo_store_bundle_xml(omemo_store_t *s, char *out, size_t outcap) {
    omemo_bundle_t b; memset(&b, 0, sizeof b);
    memcpy(b.ik_pub, s->d.id.ik_pub, 32);
    b.signed_prekey_id = s->d.spk_id;
    memcpy(b.spk_pub, s->d.spk_pub, 32);
    memcpy(b.spk_sig, s->d.spk_sig, 64);
    for (int i = 0; i < s->d.nopk && b.nprekeys < (int)(sizeof b.prekey_ids / sizeof b.prekey_ids[0]); i++) {
        if (s->d.opk[i].used) continue;
        b.prekey_ids[b.nprekeys] = s->d.opk[i].id;
        memcpy(b.prekey_pubs[b.nprekeys], s->d.opk[i].pub, 32);
        b.nprekeys++;
    }
    return omemo_bundle_build(&b, out, outcap);
}

static omemo_session_t *session_find(omemo_store_t *s, const char *bare, uint32_t dev) {
    for (int i = 0; i < s->d.nsessions; i++)
        if (s->d.sess[i].device_id == dev && !strcmp(s->d.sess[i].bare, bare)) return &s->d.sess[i].sess;
    return NULL;
}
static omemo_session_t *session_slot(omemo_store_t *s, const char *bare, uint32_t dev) {
    omemo_session_t *e = session_find(s, bare, dev); if (e) return e;
    int i = s->d.nsessions;
    if (i >= MAX_SESSIONS) { i = 0; }
    else s->d.nsessions++;
    snprintf(s->d.sess[i].bare, sizeof s->d.sess[i].bare, "%s", bare);
    s->d.sess[i].device_id = dev;
    s->d.sess[i].trust = 0;
    return &s->d.sess[i].sess;
}
static signed char session_trust(omemo_store_t *s, const char *bare, uint32_t dev) {
    for (int i = 0; i < s->d.nsessions; i++)
        if (s->d.sess[i].device_id == dev && !strcmp(s->d.sess[i].bare, bare)) return s->d.sess[i].trust;
    return 0;
}
int omemo_store_set_trust(omemo_store_t *s, const char *peer_bare, uint32_t device_id, int trust) {
    for (int i = 0; i < s->d.nsessions; i++)
        if (s->d.sess[i].device_id == device_id && !strcmp(s->d.sess[i].bare, peer_bare)) {
            s->d.sess[i].trust = (signed char)(trust < 0 ? -1 : trust > 0 ? 1 : 0);
            s->dirty = 1;
            return 0;
        }
    return -1;
}

int omemo_store_has_session(omemo_store_t *s, const char *peer_bare, uint32_t device_id) {
    return session_find(s, peer_bare, device_id) != NULL;
}
int omemo_store_peer_devices(omemo_store_t *s, const char *peer_bare, uint32_t *out, int cap) {
    int n = 0;
    for (int i = 0; i < s->d.nsessions && n < cap; i++)
        if (!strcmp(s->d.sess[i].bare, peer_bare)) out[n++] = s->d.sess[i].device_id;
    return n;
}
int omemo_store_peer_fingerprints(omemo_store_t *s, const char *peer_bare, uint32_t *devs,
        char (*fps)[65], signed char *trust, int cap) {
    static const char hex[] = "0123456789abcdef";
    int n = 0;
    for (int i = 0; i < s->d.nsessions && n < cap; i++) {
        if (strcmp(s->d.sess[i].bare, peer_bare)) continue;
        const uint8_t *ik = s->d.sess[i].sess.remote_ik;
        for (int b = 0; b < 32; b++) { fps[n][2 * b] = hex[ik[b] >> 4]; fps[n][2 * b + 1] = hex[ik[b] & 15]; }
        fps[n][64] = '\0';
        devs[n] = s->d.sess[i].device_id;
        trust[n] = s->d.sess[i].trust;
        n++;
    }
    return n;
}

int omemo_store_decrypt(omemo_store_t *s, const char *sender_bare, const char *xml,
        uint8_t *pt, size_t ptcap) {
    uint32_t sid; uint8_t keyblob[600], iv[OMEMO_IV_MAX], payload[1200]; int kbl, isp, ivlen, paylen;
    int r = omemo_envelope_parse(xml, s->d.id.device_id, &sid, keyblob, sizeof keyblob, &kbl, &isp,
                                 iv, &ivlen, payload, sizeof payload, &paylen);
    if (r == 0) return 0;
    if (r < 0) return -1;

    uint8_t keydata[64]; int kl;
    if (isp) {
        uint32_t reg, prekey_id, spk_id; uint8_t their_ik[32], their_ek[32]; const uint8_t *inner; size_t innerlen;
        if (omemo_prekey_parse(keyblob, (size_t)kbl, &reg, &prekey_id, &spk_id, their_ek, their_ik, &inner, &innerlen) != 0) return -1;
        if (spk_id != s->d.spk_id) return -1;
        int oi = -1;
        for (int i = 0; i < s->d.nopk; i++) if (s->d.opk[i].id == prekey_id && !s->d.opk[i].used) { oi = i; break; }
        const uint8_t *opk_priv = (oi >= 0) ? s->d.opk[oi].priv : NULL;
        omemo_session_t sess;
        if (omemo_x3dh_init_bob(&sess, s->d.id.ik_priv, s->d.id.ik_pub, s->d.spk_priv, s->d.spk_pub,
                                opk_priv, their_ik, their_ek) != 0) return -1;
        kl = omemo_ratchet_decrypt(&sess, inner, innerlen, keydata, sizeof keydata);
        if (kl != OMEMO_KEYDATA_LEN) return -1;
        if (oi >= 0) s->d.opk[oi].used = 1;
        *session_slot(s, sender_bare, sid) = sess;
    } else {
        omemo_session_t *sess = session_find(s, sender_bare, sid);
        if (!sess) return -1;
        kl = omemo_ratchet_decrypt(sess, keyblob, (size_t)kbl, keydata, sizeof keydata);
        if (kl != OMEMO_KEYDATA_LEN) return -1;
    }
    int pl = omemo_payload_decrypt(keydata, iv, ivlen, payload, paylen, pt, ptcap);
    if (pl >= 0) s->dirty = 1;
    return pl;
}

int omemo_store_encrypt(omemo_store_t *s, const char *peer_bare,
        const uint32_t *device_ids, const omemo_bundle_t *bundles, int ndev,
        const uint8_t *pt, size_t ptlen, char *out, size_t outcap) {
    if (ndev < 1 || ndev > 16) return -1;
    uint8_t keydata[OMEMO_KEYDATA_LEN], iv[OMEMO_IV_LEN], payload[1200]; int paylen;
    if (omemo_payload_encrypt(pt, ptlen, keydata, iv, payload, sizeof payload, &paylen) != 0) return -1;

    static uint8_t blobs[16][600]; omemo_keyslot_t slots[16]; int nslots = 0;
    for (int i = 0; i < ndev; i++) {
        omemo_session_t *sess = session_find(s, peer_bare, device_ids[i]);
        if (sess && session_trust(s, peer_bare, device_ids[i]) < 0) continue;
        int is_prekey = 0; uint8_t ek_pub[32]; uint32_t used_opk = 0;
        omemo_session_t fresh;
        if (!sess) {
            const omemo_bundle_t *b = &bundles[i];
            if (b->nprekeys < 1) continue;
            uint8_t djb[33]; djb[0] = OMEMO_DJB_TYPE; memcpy(djb + 1, b->spk_pub, 32);
            if (omemo_xeddsa_verify(b->spk_sig, b->ik_pub, djb, sizeof djb) != 0) continue;
            uint8_t ek_priv[32];
            if (omemo_x25519_keygen(ek_priv, ek_pub) != 0) return -1;
            if (omemo_x3dh_init_alice(&fresh, s->d.id.ik_priv, s->d.id.ik_pub, ek_priv,
                                      b->ik_pub, b->spk_pub, b->prekey_pubs[0]) != 0) return -1;
            used_opk = b->prekey_ids[0];
            sess = &fresh; is_prekey = 1;
        }
        uint8_t inner[512];
        int il = omemo_ratchet_encrypt(sess, keydata, sizeof keydata, inner, sizeof inner);
        if (il < 0) return -1;
        if (is_prekey) {
            int pl = omemo_prekey_serialize(blobs[nslots], sizeof blobs[nslots], s->d.id.device_id,
                        used_opk, s->d.spk_id  , ek_pub, s->d.id.ik_pub, inner, (size_t)il);

            if (pl < 0) return -1;
            slots[nslots].keyblob = blobs[nslots]; slots[nslots].keyblob_len = pl; slots[nslots].is_prekey = 1;
            *session_slot(s, peer_bare, device_ids[i]) = fresh;
        } else {
            memcpy(blobs[nslots], inner, (size_t)il);
            slots[nslots].keyblob = blobs[nslots]; slots[nslots].keyblob_len = il; slots[nslots].is_prekey = 0;
        }
        slots[nslots].device_id = device_ids[i];
        nslots++;
    }
    if (nslots == 0) return -1;
    int rc = omemo_envelope_build(s->d.id.device_id, slots, nslots, iv, payload, paylen, out, outcap);
    if (rc == 0) s->dirty = 1;
    return rc;
}

int omemo_store_selftest(void) {
    omemo_store_t *alice = omemo_store_open("selftest:alice");
    omemo_store_t *bob   = omemo_store_open("selftest:bob");
    if (!alice || !bob) { fprintf(stderr, "store: open failed\n"); return -1; }
    int rc = -1;
    uint32_t bobdev = omemo_store_device_id(bob), alicedev = omemo_store_device_id(alice);

    char bxml[8192]; omemo_bundle_t bb;
    if (omemo_store_bundle_xml(bob, bxml, sizeof bxml) != 0) { fprintf(stderr, "store: bundle build failed\n"); goto out; }
    if (omemo_bundle_parse(bxml, &bb) != 0) { fprintf(stderr, "store: bundle parse failed\n"); goto out; }

    char enc[8192]; uint8_t got[256];
    const char *m1 = "hello bob \xE2\x80\x94 first OMEMO message";
    if (omemo_store_encrypt(alice, "bob@cy-x.net", &bobdev, &bb, 1, (const uint8_t *)m1, strlen(m1), enc, sizeof enc) != 0) {
        fprintf(stderr, "store: alice encrypt failed\n"); goto out; }
    int pl = omemo_store_decrypt(bob, "alice@cy-x.net", enc, got, sizeof got);
    if (pl < 0 || (size_t)pl != strlen(m1) || memcmp(got, m1, pl) != 0) { fprintf(stderr, "store: bob decrypt(msg1) failed\n"); goto out; }
    if (!omemo_store_has_session(bob, "alice@cy-x.net", alicedev)) { fprintf(stderr, "store: bob has no session after prekey msg\n"); goto out; }

    char enc2[8192];
    const char *m2 = "hi alice, decrypted fine";
    if (omemo_store_encrypt(bob, "alice@cy-x.net", &alicedev, NULL, 1, (const uint8_t *)m2, strlen(m2), enc2, sizeof enc2) != 0) {
        fprintf(stderr, "store: bob reply encrypt failed\n"); goto out; }
    pl = omemo_store_decrypt(alice, "bob@cy-x.net", enc2, got, sizeof got);
    if (pl < 0 || (size_t)pl != strlen(m2) || memcmp(got, m2, pl) != 0) { fprintf(stderr, "store: alice decrypt(reply) failed\n"); goto out; }

    const char *m3 = "second message, same session";
    if (omemo_store_encrypt(alice, "bob@cy-x.net", &bobdev, NULL, 1, (const uint8_t *)m3, strlen(m3), enc, sizeof enc) != 0) {
        fprintf(stderr, "store: alice encrypt(msg3) failed\n"); goto out; }
    pl = omemo_store_decrypt(bob, "alice@cy-x.net", enc, got, sizeof got);
    if (pl < 0 || (size_t)pl != strlen(m3) || memcmp(got, m3, pl) != 0) { fprintf(stderr, "store: bob decrypt(msg3) failed\n"); goto out; }

    omemo_store_close(bob); bob = omemo_store_open("selftest:bob");
    if (!bob) { fprintf(stderr, "store: reopen failed\n"); goto out; }
    const char *m4 = "after a reload";
    if (omemo_store_encrypt(alice, "bob@cy-x.net", &bobdev, NULL, 1, (const uint8_t *)m4, strlen(m4), enc, sizeof enc) != 0) {
        fprintf(stderr, "store: alice encrypt(msg4) failed\n"); goto out; }
    pl = omemo_store_decrypt(bob, "alice@cy-x.net", enc, got, sizeof got);
    if (pl < 0 || (size_t)pl != strlen(m4) || memcmp(got, m4, pl) != 0) { fprintf(stderr, "store: reopened bob decrypt failed\n"); goto out; }

    if (omemo_store_set_trust(alice, "bob@cy-x.net", bobdev, -1) != 0) { fprintf(stderr, "store: set_trust failed\n"); goto out; }
    if (omemo_store_encrypt(alice, "bob@cy-x.net", &bobdev, NULL, 1, (const uint8_t *)"blocked", 7, enc, sizeof enc) == 0) {
        fprintf(stderr, "store: encrypted to an untrusted device\n"); goto out; }
    if (omemo_store_set_trust(alice, "bob@cy-x.net", bobdev, 1) != 0) { fprintf(stderr, "store: re-trust failed\n"); goto out; }
    if (omemo_store_encrypt(alice, "bob@cy-x.net", &bobdev, NULL, 1, (const uint8_t *)"unblocked", 9, enc, sizeof enc) != 0) {
        fprintf(stderr, "store: trusted-device encrypt failed\n"); goto out; }
    { uint32_t d[4]; char fps[4][65]; signed char tr[4];
      int nfp = omemo_store_peer_fingerprints(alice, "bob@cy-x.net", d, fps, tr, 4);
      if (nfp != 1 || d[0] != bobdev || tr[0] != 1 || strlen(fps[0]) != 64) { fprintf(stderr, "store: fingerprint/trust readback wrong\n"); goto out; } }

    rc = 0;
out:
    omemo_store_close(alice); omemo_store_close(bob);

    { const char *home = getenv("HOME"); char p[512];
      if (home) { snprintf(p, sizeof p, "%s/.config/trichat/omemo/selftest_alice.store", home); remove(p);
                  snprintf(p, sizeof p, "%s/.config/trichat/omemo/selftest_bob.store", home); remove(p); } }
    return rc;
}
