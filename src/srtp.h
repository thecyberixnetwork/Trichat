#ifndef TRICHAT_SRTP_H
#define TRICHAT_SRTP_H
#include <stdint.h>

#define SRTP_MASTER_KEY_LEN  16
#define SRTP_MASTER_SALT_LEN 14
#define SRTP_AUTH_TAG_LEN    10
#define SRTP_MAX_PACKET      1500

typedef struct {
    void *aes;
    uint8_t salt[14];
    uint8_t authkey[20];
    void *aes_rtcp;
    uint8_t rtcp_salt[14];
    uint8_t rtcp_authkey[20];
    uint32_t roc;
    uint16_t last_seq;
    int seq_seen;
    uint32_t rtcp_index;
    int ready;
} srtp_ctx;

int  srtp_init(srtp_ctx *c, const uint8_t master_key[16], const uint8_t master_salt[14]);
void srtp_clear(srtp_ctx *c);

int  srtp_protect(srtp_ctx *c, const uint8_t *rtp, int len, uint8_t *out);

int  srtp_unprotect(srtp_ctx *c, const uint8_t *srtp, int len, uint8_t *out);

int  srtcp_unprotect(srtp_ctx *c, const uint8_t *srtcp, int len, uint8_t *out);

int  srtcp_protect(srtp_ctx *c, const uint8_t *rtcp, int rtcp_len, uint8_t *out);

int  srtp_rtp_header_len(const uint8_t *pkt, int len);

int  srtp_selftest(void);

#endif
