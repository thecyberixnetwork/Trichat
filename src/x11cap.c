#include "x11cap.h"
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>
#include <sys/ipc.h>
#include <sys/shm.h>

struct x11cap {
    Display *dpy;
    Window   root;
    int      W, H;
    int      ow, oh, step;
    int      use_shm;
    XImage  *img;
    XShmSegmentInfo shm;
};

static int shm_err;
static int (*old_err)(Display *, XErrorEvent *);
static int shm_err_handler(Display *d, XErrorEvent *e) { (void)d; (void)e; shm_err = 1; return 0; }

static void shm_teardown(x11cap *c) {
    if (!c->use_shm) return;
    XShmDetach(c->dpy, &c->shm);
    if (c->img) { XDestroyImage(c->img); c->img = NULL; }
    if (c->shm.shmaddr && c->shm.shmaddr != (char *)-1) shmdt(c->shm.shmaddr);
    c->use_shm = 0;
}

static int shm_setup(x11cap *c, Visual *vis, int depth) {
    if (!XShmQueryExtension(c->dpy)) return 0;
    c->img = XShmCreateImage(c->dpy, vis, (unsigned)depth, ZPixmap, NULL, &c->shm,
                             (unsigned)c->W, (unsigned)c->H);
    if (!c->img) return 0;
    c->shm.shmid = shmget(IPC_PRIVATE, (size_t)c->img->bytes_per_line * c->img->height,
                          IPC_CREAT | 0600);
    if (c->shm.shmid < 0) { XDestroyImage(c->img); c->img = NULL; return 0; }
    c->shm.shmaddr = c->img->data = shmat(c->shm.shmid, NULL, 0);
    c->shm.readOnly = False;
    if (c->shm.shmaddr == (char *)-1) {
        shmctl(c->shm.shmid, IPC_RMID, NULL);
        XDestroyImage(c->img); c->img = NULL; return 0;
    }
    shm_err = 0; XSync(c->dpy, False);
    old_err = XSetErrorHandler(shm_err_handler);
    Status ok = XShmAttach(c->dpy, &c->shm);
    XSync(c->dpy, False);
    XSetErrorHandler(old_err);

    shmctl(c->shm.shmid, IPC_RMID, NULL);
    if (!ok || shm_err) {
        shmdt(c->shm.shmaddr); c->shm.shmaddr = NULL;
        XDestroyImage(c->img); c->img = NULL; return 0;
    }
    return 1;
}

x11cap *x11cap_open(int max_w) {
    x11cap *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->dpy = XOpenDisplay(NULL);
    if (!c->dpy) { free(c); return NULL; }
    int scr = DefaultScreen(c->dpy);
    c->root = RootWindow(c->dpy, scr);
    XWindowAttributes wa;
    if (!XGetWindowAttributes(c->dpy, c->root, &wa) || wa.width <= 0 || wa.height <= 0) {
        XCloseDisplay(c->dpy); free(c); return NULL;
    }
    c->W = wa.width; c->H = wa.height;
    Visual *vis = DefaultVisual(c->dpy, scr);
    int depth = DefaultDepth(c->dpy, scr);
    c->use_shm = shm_setup(c, vis, depth);

    if (max_w < 16) max_w = 16;
    c->step = 1;
    while (c->W / c->step > max_w) c->step++;
    c->ow = (c->W / c->step) & ~1;
    c->oh = (c->H / c->step) & ~1;
    if (c->ow < 2 || c->oh < 2) { x11cap_close(c); return NULL; }
    return c;
}

void x11cap_dims(const x11cap *c, int *w, int *h) {
    if (w) *w = c ? c->ow : 0;
    if (h) *h = c ? c->oh : 0;
}

int x11cap_grab(x11cap *c, uint8_t *out, int cap) {
    if (!c || !out) return -1;
    int need = c->ow * c->oh * 4;
    if (cap < need) return -1;
    XImage *im;
    if (c->use_shm) {
        if (!XShmGetImage(c->dpy, c->root, c->img, 0, 0, AllPlanes)) return -1;
        im = c->img;
    } else {
        im = XGetImage(c->dpy, c->root, 0, 0, (unsigned)c->W, (unsigned)c->H, AllPlanes, ZPixmap);
        if (!im) return -1;
    }

    if (im->bits_per_pixel != 32) { if (!c->use_shm) XDestroyImage(im); return -1; }
    int bpl = im->bytes_per_line, step = c->step;
    uint8_t *dst = out;
    for (int oy = 0; oy < c->oh; oy++) {
        const uint8_t *row = (const uint8_t *)im->data + (size_t)(oy * step) * bpl;
        if (step == 1) {
            memcpy(dst, row, (size_t)c->ow * 4);
            dst += c->ow * 4;
        } else {
            for (int ox = 0; ox < c->ow; ox++) { memcpy(dst, row + (size_t)(ox * step) * 4, 4); dst += 4; }
        }
    }
    if (!c->use_shm) XDestroyImage(im);
    return need;
}

void x11cap_close(x11cap *c) {
    if (!c) return;
    shm_teardown(c);
    if (c->dpy) XCloseDisplay(c->dpy);
    free(c);
}
