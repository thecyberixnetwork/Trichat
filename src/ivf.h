#ifndef TRICHAT_IVF_H
#define TRICHAT_IVF_H
#include <stdint.h>
#include "rtpvp8.h"

typedef struct {
    uint8_t buf[VP8_MAX_FRAME];
    int  len;
    int  header_done;
} ivf_reader;

static inline void ivf_reset(ivf_reader *r) { r->len = 0; r->header_done = 0; }

int ivf_feed(ivf_reader *r, const uint8_t *in, int inlen,
             void (*cb)(void *ud, const uint8_t *frame, int flen), void *ud);

int ivf_selftest(void);

#endif
