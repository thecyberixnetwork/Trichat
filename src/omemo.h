#ifndef TRI_OMEMO_H
#define TRI_OMEMO_H

#include <stddef.h>
#include <stdint.h>

#define OMEMO_KEY_LEN 32
#define OMEMO_SIG_LEN 64
#define OMEMO_TAG_LEN 16
#define OMEMO_IV_LEN  12

int omemo_random(void *buf, size_t n);
int omemo_x25519_keygen(uint8_t priv[OMEMO_KEY_LEN], uint8_t pub[OMEMO_KEY_LEN]);

int omemo_x25519(uint8_t out[OMEMO_KEY_LEN], const uint8_t my_priv[OMEMO_KEY_LEN],
                 const uint8_t their_pub[OMEMO_KEY_LEN]);
int omemo_ed25519_keygen(uint8_t seed[OMEMO_KEY_LEN], uint8_t pub[OMEMO_KEY_LEN]);
int omemo_ed25519_sign(uint8_t sig[OMEMO_SIG_LEN], const uint8_t seed[OMEMO_KEY_LEN],
                       const uint8_t pub[OMEMO_KEY_LEN], const void *msg, size_t n);
int omemo_ed25519_verify(const uint8_t sig[OMEMO_SIG_LEN], const uint8_t pub[OMEMO_KEY_LEN],
                         const void *msg, size_t n);
int omemo_hkdf(uint8_t *out, size_t outlen, const uint8_t *ikm, size_t ikmlen,
               const uint8_t *salt, size_t saltlen, const uint8_t *info, size_t infolen);
int omemo_aes256gcm_encrypt(uint8_t *ct, uint8_t tag[OMEMO_TAG_LEN],
                            const uint8_t key[OMEMO_KEY_LEN], const uint8_t iv[OMEMO_IV_LEN],
                            const uint8_t *pt, size_t n, const uint8_t *aad, size_t aadlen);
int omemo_aes256gcm_decrypt(uint8_t *pt, const uint8_t *ct, size_t n,
                            const uint8_t tag[OMEMO_TAG_LEN], const uint8_t key[OMEMO_KEY_LEN],
                            const uint8_t iv[OMEMO_IV_LEN], const uint8_t *aad, size_t aadlen);

int omemo_xeddsa_sign(uint8_t sig[OMEMO_SIG_LEN], const uint8_t x25519_priv[OMEMO_KEY_LEN],
                      const void *msg, size_t n);
int omemo_xeddsa_verify(const uint8_t sig[OMEMO_SIG_LEN], const uint8_t x25519_pub[OMEMO_KEY_LEN],
                        const void *msg, size_t n);

int omemo_ed_pub_from_x25519(uint8_t ed_pub[OMEMO_KEY_LEN], const uint8_t x25519_pub[OMEMO_KEY_LEN]);

typedef struct {
    uint32_t device_id;
    uint8_t  ik_priv[OMEMO_KEY_LEN];
    uint8_t  ik_pub[OMEMO_KEY_LEN];
} omemo_identity_t;

int omemo_identity_generate(omemo_identity_t *id);
int omemo_identity_save(const omemo_identity_t *id, const char *path);
int omemo_identity_load(omemo_identity_t *id, const char *path);

int omemo_identity_get(omemo_identity_t *id, const char *acct_key);

#define OMEMO_MAX_SKIP 64

typedef struct {
    uint8_t  root_key[OMEMO_KEY_LEN];
    uint8_t  dhs_priv[OMEMO_KEY_LEN], dhs_pub[OMEMO_KEY_LEN];
    uint8_t  dhr[OMEMO_KEY_LEN];      int have_dhr;
    uint8_t  cks[OMEMO_KEY_LEN];      int has_cks;
    uint8_t  ckr[OMEMO_KEY_LEN];      int has_ckr;
    uint8_t  local_ik[OMEMO_KEY_LEN], remote_ik[OMEMO_KEY_LEN];
    uint32_t ns, nr, pn;
    struct { uint8_t dhr[OMEMO_KEY_LEN]; uint32_t n; uint8_t mk[OMEMO_KEY_LEN]; } skipped[OMEMO_MAX_SKIP];
    int      nskip;
} omemo_session_t;

int omemo_x3dh_init_alice(omemo_session_t *s,
        const uint8_t ik_priv[OMEMO_KEY_LEN], const uint8_t ik_pub[OMEMO_KEY_LEN],
        const uint8_t ek_priv[OMEMO_KEY_LEN],
        const uint8_t their_ik_pub[OMEMO_KEY_LEN], const uint8_t their_spk_pub[OMEMO_KEY_LEN],
        const uint8_t *their_opk_pub  );

int omemo_x3dh_init_bob(omemo_session_t *s,
        const uint8_t ik_priv[OMEMO_KEY_LEN], const uint8_t ik_pub[OMEMO_KEY_LEN],
        const uint8_t spk_priv[OMEMO_KEY_LEN], const uint8_t spk_pub[OMEMO_KEY_LEN],
        const uint8_t *opk_priv  ,
        const uint8_t their_ik_pub[OMEMO_KEY_LEN], const uint8_t their_ek_pub[OMEMO_KEY_LEN]);

int omemo_ratchet_encrypt(omemo_session_t *s, const uint8_t *pt, size_t ptlen,
        uint8_t *out, size_t outcap);
int omemo_ratchet_decrypt(omemo_session_t *s, const uint8_t *wire, size_t wirelen,
        uint8_t *pt, size_t ptcap);

#define OMEMO_WIRE_VERSION 0x33
#define OMEMO_MAX_CIPHERTEXT 512
#define OMEMO_DJB_TYPE 0x05

int omemo_signal_serialize(uint8_t *out, size_t outcap,
        const uint8_t ratchet_pub[OMEMO_KEY_LEN], uint32_t counter, uint32_t prev_counter,
        const uint8_t *ct, size_t ctlen);
int omemo_signal_parse(const uint8_t *in, size_t inlen,
        uint8_t ratchet_pub[OMEMO_KEY_LEN], uint32_t *counter, uint32_t *prev_counter,
        const uint8_t **ct, size_t *ctlen);

int omemo_prekey_serialize(uint8_t *out, size_t outcap,
        uint32_t registration_id, uint32_t prekey_id, uint32_t signed_prekey_id,
        const uint8_t base_pub[OMEMO_KEY_LEN], const uint8_t identity_pub[OMEMO_KEY_LEN],
        const uint8_t *inner_msg, size_t inner_len);
int omemo_prekey_parse(const uint8_t *in, size_t inlen,
        uint32_t *registration_id, uint32_t *prekey_id, uint32_t *signed_prekey_id,
        uint8_t base_pub[OMEMO_KEY_LEN], uint8_t identity_pub[OMEMO_KEY_LEN],
        const uint8_t **inner_msg, size_t *inner_len);

#define OMEMO_NS         "eu.siacs.conversations.axolotl"
#define OMEMO_GCM_KEYLEN 16
#define OMEMO_IV_MAX     16

typedef struct { uint32_t device_id; omemo_session_t *session; } omemo_recipient_t;

int omemo_envelope_encrypt(uint32_t sender_device_id, const omemo_recipient_t *rcpts, int nrcpts,
        const uint8_t *pt, size_t ptlen, char *out, size_t outcap);

int omemo_envelope_decrypt(const char *xml, uint32_t my_device_id, omemo_session_t *session,
        uint8_t *pt, size_t ptcap);

#define OMEMO_KEYDATA_LEN (OMEMO_GCM_KEYLEN + OMEMO_TAG_LEN)

int omemo_payload_encrypt(const uint8_t *pt, size_t ptlen,
        uint8_t keydata[OMEMO_KEYDATA_LEN], uint8_t iv[OMEMO_IV_LEN],
        uint8_t *payload, size_t paycap, int *paylen);

int omemo_payload_decrypt(const uint8_t keydata[OMEMO_KEYDATA_LEN], const uint8_t *iv, int ivlen,
        const uint8_t *payload, int paylen, uint8_t *pt, size_t ptcap);

typedef struct { uint32_t device_id; const uint8_t *keyblob; int keyblob_len; int is_prekey; } omemo_keyslot_t;
int omemo_envelope_build(uint32_t sender_device_id, const omemo_keyslot_t *slots, int nslots,
        const uint8_t iv[OMEMO_IV_LEN], const uint8_t *payload, int paylen, char *out, size_t outcap);

int omemo_envelope_parse(const char *xml, uint32_t my_device_id, uint32_t *sender_sid,
        uint8_t *keyblob, size_t keyblobcap, int *keyblob_len, int *is_prekey,
        uint8_t iv[OMEMO_IV_MAX], int *ivlen, uint8_t *payload, size_t paycap, int *paylen);

int omemo_devicelist_build(const uint32_t *ids, int n, char *out, size_t outcap);
int omemo_devicelist_parse(const char *xml, uint32_t *ids, int cap);

typedef struct {
    uint8_t  ik_pub[OMEMO_KEY_LEN];
    uint32_t signed_prekey_id; uint8_t spk_pub[OMEMO_KEY_LEN]; uint8_t spk_sig[OMEMO_SIG_LEN];
    uint32_t prekey_ids[150];  uint8_t prekey_pubs[150][OMEMO_KEY_LEN]; int nprekeys;
} omemo_bundle_t;
int omemo_bundle_build(const omemo_bundle_t *b, char *out, size_t outcap);
int omemo_bundle_parse(const char *xml, omemo_bundle_t *b);

typedef struct omemo_store omemo_store_t;

omemo_store_t *omemo_store_open(const char *acct_key);
void     omemo_store_close(omemo_store_t *s);
void     omemo_store_flush(omemo_store_t *s);
uint32_t omemo_store_device_id(const omemo_store_t *s);

int omemo_store_bundle_xml(omemo_store_t *s, char *out, size_t outcap);

int omemo_store_fingerprint(omemo_store_t *s, char *out, size_t outcap);

int omemo_store_decrypt(omemo_store_t *s, const char *sender_bare, const char *xml,
        uint8_t *pt, size_t ptcap);

int omemo_store_encrypt(omemo_store_t *s, const char *peer_bare,
        const uint32_t *device_ids, const omemo_bundle_t *bundles, int ndev,
        const uint8_t *pt, size_t ptlen, char *out, size_t outcap);
int omemo_store_has_session(omemo_store_t *s, const char *peer_bare, uint32_t device_id);

int omemo_store_peer_devices(omemo_store_t *s, const char *peer_bare, uint32_t *out, int cap);

int omemo_store_peer_fingerprints(omemo_store_t *s, const char *peer_bare, uint32_t *devs,
        char (*fps)[65], signed char *trust, int cap);

int omemo_store_set_trust(omemo_store_t *s, const char *peer_bare, uint32_t device_id, int trust);

int omemo_selftest(void);
int omemo_wire_selftest(void);
int omemo_session_selftest(void);
int omemo_envelope_selftest(void);
int omemo_store_selftest(void);

#endif
