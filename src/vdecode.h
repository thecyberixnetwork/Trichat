#ifndef TRICHAT_VDECODE_H
#define TRICHAT_VDECODE_H
#include <stdint.h>

typedef struct tri_vdec tri_vdec;

tri_vdec *tri_vdec_new(const char *codec);

int tri_vdec_feed(tri_vdec *d, const uint8_t *data, int len,
                  uint8_t *(*acquire)(void *ud, int w, int h),
                  void (*commit)(void *ud, int w, int h), void *ud);

void tri_vdec_free(tri_vdec *d);

typedef struct tri_vdec_async tri_vdec_async;
tri_vdec_async *tri_vdec_async_new(const char *codec);

int  tri_vdec_async_feed(tri_vdec_async *d, const uint8_t *data, int len);

int  tri_vdec_async_fd(tri_vdec_async *d);

void tri_vdec_async_drain(tri_vdec_async *d, void (*publish)(void *ud, int w, int h, const uint8_t *rgba), void *ud);

int  tri_vdec_async_fatal(tri_vdec_async *d);
void tri_vdec_async_free(tri_vdec_async *d);

#endif
