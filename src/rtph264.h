#ifndef TRICHAT_RTPH264_H
#define TRICHAT_RTPH264_H
#include <stdint.h>

#define H264_MAX_FRAG   256
#define H264_BUF        524288

typedef struct { uint8_t data[1500]; int len; } h264_frag;

int h264_nal_type(const uint8_t *nal, int nlen);

int h264_packetize(const uint8_t *nal, int nlen, int payload_mtu, h264_frag *out, int maxfrag);

typedef struct { uint8_t buf[H264_BUF]; int len; } h264_reader;
static inline void h264_reader_reset(h264_reader *r) { r->len = 0; }
int h264_feed(h264_reader *r, const uint8_t *in, int inlen,
              void (*cb)(void *ud, const uint8_t *nal, int nlen), void *ud);

typedef struct { uint8_t buf[H264_BUF]; int len; int active; } h264_depacketizer;
static inline void h264_depkt_reset(h264_depacketizer *d) { d->len = 0; d->active = 0; }
int h264_depacketize(h264_depacketizer *d, const uint8_t *pl, int plen, uint8_t *out, int out_cap);

int h264_selftest(void);

#endif
