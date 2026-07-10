#ifndef TRICHAT_X11CAP_H
#define TRICHAT_X11CAP_H
#include <stdint.h>

typedef struct x11cap x11cap;

x11cap *x11cap_open(int max_w);

void x11cap_dims(const x11cap *c, int *w, int *h);

int x11cap_grab(x11cap *c, uint8_t *out, int cap);

void x11cap_close(x11cap *c);

#endif
