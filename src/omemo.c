#include "omemo.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>

int omemo_random(void *buf, size_t n) {
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) return -1;
    int rc = wc_RNG_GenerateBlock(&rng, (byte *)buf, (word32)n);
    wc_FreeRng(&rng);
    return rc == 0 ? 0 : -1;
}

int omemo_x25519_keygen(uint8_t priv[OMEMO_KEY_LEN], uint8_t pub[OMEMO_KEY_LEN]) {
    WC_RNG rng; curve25519_key k;
    if (wc_InitRng(&rng) != 0) return -1;
    int rc = -1;
    if (wc_curve25519_init(&k) == 0) {
        if (wc_curve25519_make_key(&rng, OMEMO_KEY_LEN, &k) == 0) {
            word32 pl = OMEMO_KEY_LEN, sl = OMEMO_KEY_LEN;
            if (wc_curve25519_export_private_raw_ex(&k, priv, &pl, EC25519_LITTLE_ENDIAN) == 0 &&
                wc_curve25519_export_public_ex(&k, pub, &pl, EC25519_LITTLE_ENDIAN) == 0)
                rc = 0;
            (void)sl;
        }
        wc_curve25519_free(&k);
    }
    wc_FreeRng(&rng);
    return rc;
}

int omemo_x25519(uint8_t out[OMEMO_KEY_LEN], const uint8_t my_priv[OMEMO_KEY_LEN],
                 const uint8_t their_pub[OMEMO_KEY_LEN]) {
    curve25519_key mine, theirs; WC_RNG rng;
    int rc = -1;
    if (wc_InitRng(&rng) != 0) return -1;
    if (wc_curve25519_init(&mine) != 0) { wc_FreeRng(&rng); return -1; }
    if (wc_curve25519_init(&theirs) != 0) { wc_curve25519_free(&mine); wc_FreeRng(&rng); return -1; }

    if (wc_curve25519_import_private_ex(my_priv, OMEMO_KEY_LEN, &mine, EC25519_LITTLE_ENDIAN) == 0 &&
        wc_curve25519_set_rng(&mine, &rng) == 0 &&
        wc_curve25519_import_public_ex(their_pub, OMEMO_KEY_LEN, &theirs, EC25519_LITTLE_ENDIAN) == 0) {
        word32 ol = OMEMO_KEY_LEN;
        if (wc_curve25519_shared_secret_ex(&mine, &theirs, out, &ol, EC25519_LITTLE_ENDIAN) == 0 && ol == OMEMO_KEY_LEN) {
            uint8_t zero = 0; for (int i = 0; i < OMEMO_KEY_LEN; i++) zero |= out[i];
            if (zero) rc = 0;
        }
    }
    wc_curve25519_free(&mine); wc_curve25519_free(&theirs); wc_FreeRng(&rng);
    return rc;
}

int omemo_ed25519_keygen(uint8_t seed[OMEMO_KEY_LEN], uint8_t pub[OMEMO_KEY_LEN]) {
    WC_RNG rng; ed25519_key k;
    if (wc_InitRng(&rng) != 0) return -1;
    int rc = -1;
    if (wc_ed25519_init(&k) == 0) {
        if (wc_ed25519_make_key(&rng, OMEMO_KEY_LEN, &k) == 0) {
            word32 sl = OMEMO_KEY_LEN, pl = OMEMO_KEY_LEN;
            if (wc_ed25519_export_private_only(&k, seed, &sl) == 0 &&
                wc_ed25519_export_public(&k, pub, &pl) == 0)
                rc = 0;
        }
        wc_ed25519_free(&k);
    }
    wc_FreeRng(&rng);
    return rc;
}

int omemo_ed25519_sign(uint8_t sig[OMEMO_SIG_LEN], const uint8_t seed[OMEMO_KEY_LEN],
                       const uint8_t pub[OMEMO_KEY_LEN], const void *msg, size_t n) {
    ed25519_key k; int rc = -1;
    if (wc_ed25519_init(&k) != 0) return -1;
    if (wc_ed25519_import_private_key(seed, OMEMO_KEY_LEN, pub, OMEMO_KEY_LEN, &k) == 0) {
        word32 sl = OMEMO_SIG_LEN;
        if (wc_ed25519_sign_msg((const byte *)msg, (word32)n, sig, &sl, &k) == 0 && sl == OMEMO_SIG_LEN)
            rc = 0;
    }
    wc_ed25519_free(&k);
    return rc;
}

int omemo_ed25519_verify(const uint8_t sig[OMEMO_SIG_LEN], const uint8_t pub[OMEMO_KEY_LEN],
                         const void *msg, size_t n) {
    ed25519_key k; int rc = -1, ok = 0;
    if (wc_ed25519_init(&k) != 0) return -1;
    if (wc_ed25519_import_public(pub, OMEMO_KEY_LEN, &k) == 0 &&
        wc_ed25519_verify_msg(sig, OMEMO_SIG_LEN, (const byte *)msg, (word32)n, &ok, &k) == 0 && ok)
        rc = 0;
    wc_ed25519_free(&k);
    return rc;
}

int omemo_hkdf(uint8_t *out, size_t outlen, const uint8_t *ikm, size_t ikmlen,
               const uint8_t *salt, size_t saltlen, const uint8_t *info, size_t infolen) {
    return wc_HKDF(WC_SHA256, ikm, (word32)ikmlen, salt, (word32)saltlen,
                   info, (word32)infolen, out, (word32)outlen) == 0 ? 0 : -1;
}

int omemo_aes256gcm_encrypt(uint8_t *ct, uint8_t tag[OMEMO_TAG_LEN],
                            const uint8_t key[OMEMO_KEY_LEN], const uint8_t iv[OMEMO_IV_LEN],
                            const uint8_t *pt, size_t n, const uint8_t *aad, size_t aadlen) {
    Aes aes; int rc = -1;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_AesGcmSetKey(&aes, key, OMEMO_KEY_LEN) == 0 &&
        wc_AesGcmEncrypt(&aes, ct, pt, (word32)n, iv, OMEMO_IV_LEN, tag, OMEMO_TAG_LEN, aad, (word32)aadlen) == 0)
        rc = 0;
    wc_AesFree(&aes);
    return rc;
}

int omemo_aes256gcm_decrypt(uint8_t *pt, const uint8_t *ct, size_t n,
                            const uint8_t tag[OMEMO_TAG_LEN], const uint8_t key[OMEMO_KEY_LEN],
                            const uint8_t iv[OMEMO_IV_LEN], const uint8_t *aad, size_t aadlen) {
    Aes aes; int rc = -1;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_AesGcmSetKey(&aes, key, OMEMO_KEY_LEN) == 0 &&
        wc_AesGcmDecrypt(&aes, pt, ct, (word32)n, iv, OMEMO_IV_LEN, tag, OMEMO_TAG_LEN, aad, (word32)aadlen) == 0)
        rc = 0;
    wc_AesFree(&aes);
    return rc;
}

int omemo_identity_generate(omemo_identity_t *id) {
    memset(id, 0, sizeof *id);
    if (omemo_x25519_keygen(id->ik_priv, id->ik_pub) != 0) return -1;

    do { if (omemo_random(&id->device_id, sizeof id->device_id) != 0) return -1;
         id->device_id &= 0x7fffffffu; } while (id->device_id == 0);
    return 0;
}

int omemo_identity_save(const omemo_identity_t *id, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    char priv[2 * OMEMO_KEY_LEN + 1], pub[2 * OMEMO_KEY_LEN + 1];
    tri_hexenc(id->ik_priv, OMEMO_KEY_LEN, priv);
    tri_hexenc(id->ik_pub, OMEMO_KEY_LEN, pub);

    int ok = fprintf(f, "v1\t%u\t%s\t%s\n", id->device_id, priv, pub) > 0;
    fclose(f);
    if (ok) chmod(path, 0600);
    return ok ? 0 : -1;
}

int omemo_identity_load(omemo_identity_t *id, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    int rc = -1;
    if (fgets(line, sizeof line, f)) {
        char priv[2 * OMEMO_KEY_LEN + 2] = "", pub[2 * OMEMO_KEY_LEN + 2] = "";
        unsigned dev = 0;
        if (sscanf(line, "v1\t%u\t%64[0-9a-fA-F]\t%64[0-9a-fA-F]", &dev, priv, pub) == 3 &&
            strlen(priv) == 2 * OMEMO_KEY_LEN && strlen(pub) == 2 * OMEMO_KEY_LEN) {
            memset(id, 0, sizeof *id);
            id->device_id = dev;
            if (tri_hexdec(priv, id->ik_priv, OMEMO_KEY_LEN) == 0 &&
                tri_hexdec(pub, id->ik_pub, OMEMO_KEY_LEN) == 0 && dev != 0)
                rc = 0;
        }
    }
    fclose(f);
    return rc;
}

static void mkdir_p(const char *path) {
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    mkdir(tmp, 0700);
}

int omemo_identity_get(omemo_identity_t *id, const char *acct_key) {
    const char *home = getenv("HOME"); if (!home) home = ".";
    char dir[512]; snprintf(dir, sizeof dir, "%s/.config/trichat/omemo", home);
    mkdir_p(dir);
    char safe[128]; snprintf(safe, sizeof safe, "%s", acct_key);
    for (char *p = safe; *p; p++) if (*p == '/' || *p == ':') *p = '_';
    char path[700]; snprintf(path, sizeof path, "%s/%s.id", dir, safe);
    if (omemo_identity_load(id, path) == 0) return 0;
    if (omemo_identity_generate(id) != 0) return -1;
    return omemo_identity_save(id, path);
}

static int eq(const uint8_t *a, const uint8_t *b, size_t n, const char *what) {
    if (memcmp(a, b, n) == 0) return 0;
    fprintf(stderr, "omemo selftest: %s mismatch\n", what);
    return -1;
}

int omemo_selftest(void) {
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], want_pub[32], want_ss[32], ss[32];
    tri_hexdec("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv, 32);
    tri_hexdec("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", want_pub, 32);
    tri_hexdec("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv, 32);
    tri_hexdec("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pub, 32);
    tri_hexdec("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want_ss, 32);
    (void)a_pub;

    if (omemo_x25519(ss, a_priv, b_pub) != 0 || eq(ss, want_ss, 32, "x25519 shared") != 0) return -1;

    if (omemo_x25519(ss, b_priv, want_pub) != 0 || eq(ss, want_ss, 32, "x25519 symmetry") != 0) return -1;

    {
        uint8_t seed[32], epub[32], sig[64];
        const char *m = "the quick brown fox";
        if (omemo_ed25519_keygen(seed, epub) != 0) return -1;
        if (omemo_ed25519_sign(sig, seed, epub, m, strlen(m)) != 0) return -1;
        if (omemo_ed25519_verify(sig, epub, m, strlen(m)) != 0) { fprintf(stderr, "omemo selftest: ed25519 verify failed\n"); return -1; }
        sig[0] ^= 1;
        if (omemo_ed25519_verify(sig, epub, m, strlen(m)) == 0) { fprintf(stderr, "omemo selftest: ed25519 accepted a bad sig\n"); return -1; }
    }

    uint8_t ikm[22], salt[13], info[10], okm[42], want_okm[42];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
    tri_hexdec("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", want_okm, 42);
    if (omemo_hkdf(okm, 42, ikm, sizeof ikm, salt, sizeof salt, info, sizeof info) != 0 ||
        eq(okm, want_okm, 42, "hkdf okm") != 0) return -1;

    {
        uint8_t key[32], iv[12], pt[19] = "omemo payload test", ct[19], out[19], tag[16];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(0xa0 + i);
        if (omemo_aes256gcm_encrypt(ct, tag, key, iv, pt, sizeof pt, NULL, 0) != 0) return -1;
        if (omemo_aes256gcm_decrypt(out, ct, sizeof ct, tag, key, iv, NULL, 0) != 0 ||
            eq(out, pt, sizeof pt, "gcm roundtrip") != 0) return -1;
        tag[0] ^= 1;
        if (omemo_aes256gcm_decrypt(out, ct, sizeof ct, tag, key, iv, NULL, 0) == 0) {
            fprintf(stderr, "omemo selftest: gcm accepted a forged tag\n"); return -1;
        }
    }

    {
        uint8_t xpriv[32], xpub[32], sig[64], edpub[32];
        const char *m = "OMEMO signed prekey";
        if (omemo_x25519_keygen(xpriv, xpub) != 0) return -1;
        if (omemo_xeddsa_sign(sig, xpriv, m, strlen(m)) != 0) return -1;
        if (omemo_xeddsa_verify(sig, xpub, m, strlen(m)) != 0) { fprintf(stderr, "omemo selftest: xeddsa verify failed\n"); return -1; }
        uint8_t bad[64]; memcpy(bad, sig, 64); bad[10] ^= 1;
        if (omemo_xeddsa_verify(bad, xpub, m, strlen(m)) == 0) { fprintf(stderr, "omemo selftest: xeddsa accepted a tampered sig\n"); return -1; }
        if (omemo_xeddsa_verify(sig, xpub, "OMEMO signed prekeX", strlen(m)) == 0) { fprintf(stderr, "omemo selftest: xeddsa accepted a wrong message\n"); return -1; }
        uint8_t otherpriv[32], otherpub[32];
        if (omemo_x25519_keygen(otherpriv, otherpub) != 0) return -1;
        if (omemo_xeddsa_verify(sig, otherpub, m, strlen(m)) == 0) { fprintf(stderr, "omemo selftest: xeddsa accepted a wrong key\n"); return -1; }

        if (omemo_ed_pub_from_x25519(edpub, xpub) != 0) return -1;
        ed25519_key ek; int ok = 0;
        if (wc_ed25519_init(&ek) != 0) return -1;
        int cross = (wc_ed25519_import_public(edpub, 32, &ek) == 0 &&
                     wc_ed25519_verify_msg(sig, 64, (const byte *)m, (word32)strlen(m), &ok, &ek) == 0 && ok);
        wc_ed25519_free(&ek);
        if (!cross) { fprintf(stderr, "omemo selftest: xeddsa sig rejected by independent Ed25519 verifier\n"); return -1; }
    }

    {
        omemo_identity_t id, back;
        if (omemo_identity_generate(&id) != 0) return -1;
        const char *tmp = "/tmp/.trichat_omemo_selftest.id";
        if (omemo_identity_save(&id, tmp) != 0) return -1;
        if (omemo_identity_load(&back, tmp) != 0) return -1;
        remove(tmp);
        if (back.device_id != id.device_id || eq(back.ik_priv, id.ik_priv, 32, "identity priv") != 0 ||
            eq(back.ik_pub, id.ik_pub, 32, "identity pub") != 0) return -1;

        omemo_identity_t id2;
        if (omemo_identity_generate(&id2) != 0) return -1;
        if (id2.device_id == id.device_id && memcmp(id2.ik_priv, id.ik_priv, 32) == 0) {
            fprintf(stderr, "omemo selftest: identity generation not random\n"); return -1;
        }
    }
    return 0;
}
