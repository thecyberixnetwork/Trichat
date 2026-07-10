#ifndef TRICHAT_STUN_H
#define TRICHAT_STUN_H
#include <stdint.h>
#include <stddef.h>

#define STUN_MAGIC_COOKIE 0x2112A442u
#define STUN_TXID_LEN     12
#define STUN_HEADER_LEN   20

#define STUN_BINDING_REQUEST  0x0001
#define STUN_BINDING_SUCCESS  0x0101
#define STUN_BINDING_ERROR    0x0111

#define TURN_ALLOCATE_REQUEST     0x0003
#define TURN_ALLOCATE_SUCCESS     0x0103
#define TURN_ALLOCATE_ERROR       0x0113
#define TURN_REFRESH_REQUEST      0x0004
#define TURN_REFRESH_SUCCESS      0x0104
#define TURN_REFRESH_ERROR        0x0114
#define TURN_CREATEPERM_REQUEST   0x0008
#define TURN_CREATEPERM_SUCCESS   0x0108
#define TURN_CREATEPERM_ERROR     0x0118
#define TURN_SEND_INDICATION      0x0016
#define TURN_DATA_INDICATION      0x0017

enum {
    STUN_ATTR_MAPPED_ADDRESS     = 0x0001,
    STUN_ATTR_USERNAME           = 0x0006,
    STUN_ATTR_MESSAGE_INTEGRITY  = 0x0008,
    STUN_ATTR_ERROR_CODE         = 0x0009,
    STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
    STUN_ATTR_PRIORITY           = 0x0024,
    STUN_ATTR_USE_CANDIDATE      = 0x0025,
    STUN_ATTR_FINGERPRINT        = 0x8028,
    STUN_ATTR_ICE_CONTROLLED     = 0x8029,
    STUN_ATTR_ICE_CONTROLLING    = 0x802A,

    STUN_ATTR_CHANNEL_NUMBER     = 0x000C,
    STUN_ATTR_LIFETIME           = 0x000D,
    STUN_ATTR_XOR_PEER_ADDRESS   = 0x0012,
    STUN_ATTR_DATA               = 0x0013,
    STUN_ATTR_REALM              = 0x0014,
    STUN_ATTR_NONCE              = 0x0015,
    STUN_ATTR_XOR_RELAYED_ADDRESS= 0x0016,
    STUN_ATTR_REQUESTED_TRANSPORT= 0x0019
};

int stun_longterm_key(const char *user, const char *realm, const char *pass, uint8_t out[16]);

int stun_error_code(const uint8_t *buf, size_t len);

typedef struct {
    int      family;
    uint8_t  addr[16];
    uint16_t port;
} stun_addr;

typedef struct { uint8_t *buf; size_t cap; size_t len; int err; } stun_msg;

void stun_begin(stun_msg *m, uint8_t *buf, size_t cap, uint16_t type, const uint8_t txid[STUN_TXID_LEN]);
void stun_add_bytes(stun_msg *m, uint16_t type, const void *data, uint16_t len);
void stun_add_u32(stun_msg *m, uint16_t type, uint32_t v);
void stun_add_u64(stun_msg *m, uint16_t type, uint64_t v);
void stun_add_flag(stun_msg *m, uint16_t type);
void stun_add_xor_addr(stun_msg *m, uint16_t type, const stun_addr *a);
int  stun_add_integrity(stun_msg *m, const char *key, size_t keylen);
int  stun_add_fingerprint(stun_msg *m);
int  stun_finish(stun_msg *m);

int  stun_check(const uint8_t *buf, size_t len);
uint16_t       stun_type(const uint8_t *buf);
const uint8_t *stun_txid(const uint8_t *buf);
const uint8_t *stun_find(const uint8_t *buf, size_t len, uint16_t type, uint16_t *vlen);
int  stun_get_xor_addr(const uint8_t *buf, size_t len, uint16_t type, stun_addr *out);
int  stun_verify_integrity(const uint8_t *buf, size_t len, const char *key, size_t keylen);
int  stun_verify_fingerprint(const uint8_t *buf, size_t len);

int  stun_selftest(void);

#endif
