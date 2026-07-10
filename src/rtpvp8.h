#ifndef TRICHAT_RTPVP8_H
#define TRICHAT_RTPVP8_H
#include <stdint.h>

#define VP8_MAX_FRAG   64
#define VP8_MAX_FRAME  262144

typedef struct { uint8_t data[1500]; int len; int marker; } vp8_frag;

int vp8_packetize(const uint8_t *frame, int flen, int payload_mtu, vp8_frag *out, int maxfrag);

typedef struct { uint8_t buf[VP8_MAX_FRAME]; int len; int in_frame; } vp8_reasm;

int vp8_depacketize(vp8_reasm *r, const uint8_t *payload, int plen, int marker,
                    const uint8_t **frame, int *flen);

int vp8_is_keyframe(const uint8_t *frame, int flen);

int vp8_selftest(void);

#endif
