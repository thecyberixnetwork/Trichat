#ifndef TRICHAT_DTLS_H
#define TRICHAT_DTLS_H
#include <stdint.h>

typedef struct dtls_srtp dtls_srtp;
typedef void (*dtls_send_fn)(void *ud, const uint8_t *data, int len);

dtls_srtp  *dtls_srtp_new(int client, dtls_send_fn send, void *send_ud);
void        dtls_srtp_free(dtls_srtp *d);
void        dtls_srtp_set_send(dtls_srtp *d, dtls_send_fn send, void *send_ud);

const char *dtls_srtp_fingerprint(dtls_srtp *d);
void        dtls_srtp_set_peer_fingerprint(dtls_srtp *d, const char *fp);

int  dtls_srtp_start(dtls_srtp *d);
int  dtls_srtp_feed(dtls_srtp *d, const uint8_t *data, int len);
int  dtls_srtp_tick(dtls_srtp *d);
int  dtls_srtp_done(const dtls_srtp *d);
int  dtls_srtp_failed(const dtls_srtp *d);
const char *dtls_srtp_error(const dtls_srtp *d);
const char *dtls_srtp_profile(const dtls_srtp *d);

int  dtls_srtp_keys(const dtls_srtp *d, uint8_t *out, int cap);

int  dtls_srtp_selftest(void);

#endif
