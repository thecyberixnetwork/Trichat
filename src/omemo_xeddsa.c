#include "omemo.h"
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ge_operations.h>
#include <wolfssl/wolfcrypt/fe_operations.h>
#include <wolfssl/wolfcrypt/sha512.h>

static const byte L_MINUS_1[32] = {
    0xec,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

static const byte HASH1_PREFIX[32] = {
    0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

int omemo_ed_pub_from_x25519(uint8_t ed_pub[OMEMO_KEY_LEN], const uint8_t x25519_pub[OMEMO_KEY_LEN]) {
    fe u, y, one, num, den, inv;
    fe_frombytes(u, x25519_pub);
    fe_1(one);
    fe_sub(num, u, one);
    fe_add(den, u, one);
    if (!fe_isnonzero(den)) return -1;
    fe_invert(inv, den);
    fe_mul(y, num, inv);
    fe_tobytes(ed_pub, y);
    return 0;
}

int omemo_xeddsa_sign(uint8_t sig[OMEMO_SIG_LEN], const uint8_t x25519_priv[OMEMO_KEY_LEN],
                      const void *msg, size_t n) {
    byte Z[64];
    if (omemo_random(Z, sizeof Z) != 0) return -1;

    byte k[32]; memcpy(k, x25519_priv, 32);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;

    ge_p3 Ap; ge_scalarmult_base(&Ap, k);
    byte A[32]; ge_p3_tobytes(A, &Ap);
    byte a[32]; memcpy(a, k, 32);
    if (A[31] & 0x80) { byte zero[32] = {0}; sc_muladd(a, L_MINUS_1, k, zero); }
    A[31] &= 0x7f;

    byte r[64];
    { wc_Sha512 s; wc_InitSha512(&s);
      wc_Sha512Update(&s, HASH1_PREFIX, 32); wc_Sha512Update(&s, a, 32);
      wc_Sha512Update(&s, (const byte *)msg, (word32)n); wc_Sha512Update(&s, Z, 64);
      wc_Sha512Final(&s, r); }
    sc_reduce(r);

    ge_p3 Rp; ge_scalarmult_base(&Rp, r);
    byte R[32]; ge_p3_tobytes(R, &Rp);

    byte h[64];
    { wc_Sha512 s; wc_InitSha512(&s);
      wc_Sha512Update(&s, R, 32); wc_Sha512Update(&s, A, 32);
      wc_Sha512Update(&s, (const byte *)msg, (word32)n);
      wc_Sha512Final(&s, h); }
    sc_reduce(h);

    byte S[32]; sc_muladd(S, h, a, r);

    memcpy(sig, R, 32); memcpy(sig + 32, S, 32);

    memset(k, 0, sizeof k); memset(a, 0, sizeof a); memset(r, 0, sizeof r); memset(Z, 0, sizeof Z);
    return 0;
}

int omemo_xeddsa_verify(const uint8_t sig[OMEMO_SIG_LEN], const uint8_t x25519_pub[OMEMO_KEY_LEN],
                        const void *msg, size_t n) {
    if (sig[63] & 0xe0) return -1;

    byte A[32];
    if (omemo_ed_pub_from_x25519(A, x25519_pub) != 0) return -1;

    ge_p3 negA;
    if (ge_frombytes_negate_vartime(&negA, A) != 0) return -1;

    byte h[64];
    { wc_Sha512 s; wc_InitSha512(&s);
      wc_Sha512Update(&s, sig, 32); wc_Sha512Update(&s, A, 32);
      wc_Sha512Update(&s, (const byte *)msg, (word32)n);
      wc_Sha512Final(&s, h); }
    sc_reduce(h);

    ge_p2 Rp; ge_double_scalarmult_vartime(&Rp, h, &negA, sig + 32);
    byte Rcheck[32]; ge_tobytes(Rcheck, &Rp);
    return memcmp(Rcheck, sig, 32) == 0 ? 0 : -1;
}
