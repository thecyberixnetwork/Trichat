#include "vdecode.h"
#include <stdlib.h>
#include <string.h>

#ifdef TRI_AVCODEC
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libswscale/swscale.h>

struct tri_vdec {
    AVCodecContext  *ctx;
    AVPacket        *pkt;
    AVFrame         *frame;
    struct SwsContext *sws;
    int              sws_w, sws_h, sws_fmt;
};

tri_vdec *tri_vdec_new(const char *codec) {
    if (!codec) return NULL;
    enum AVCodecID id;
    if      (!strcasecmp(codec, "VP8"))  id = AV_CODEC_ID_VP8;
    else if (!strcasecmp(codec, "H264")) id = AV_CODEC_ID_H264;
    else return NULL;
    const AVCodec *dec = avcodec_find_decoder(id);
    if (!dec) return NULL;
    tri_vdec *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->ctx   = avcodec_alloc_context3(dec);
    d->pkt   = av_packet_alloc();
    d->frame = av_frame_alloc();
    if (!d->ctx || !d->pkt || !d->frame) { tri_vdec_free(d); return NULL; }

    d->ctx->flags |= AV_CODEC_FLAG_LOW_DELAY;
    d->ctx->thread_count = 1;
    if (avcodec_open2(d->ctx, dec, NULL) < 0) { tri_vdec_free(d); return NULL; }
    return d;
}

#define VDEC_MAX_W 640
#define VDEC_MAX_H 480

static void emit_frame(tri_vdec *d, uint8_t *(*acquire)(void *, int, int),
                       void (*commit)(void *, int, int), void *ud) {
    int sw = d->frame->width, sh = d->frame->height;
    if (sw <= 0 || sh <= 0) return;
    int w = sw, h = sh;
    if (w > VDEC_MAX_W || h > VDEC_MAX_H) {
        double s = (double)VDEC_MAX_W / w; if ((double)VDEC_MAX_H / h < s) s = (double)VDEC_MAX_H / h;
        w = (int)(sw * s); h = (int)(sh * s);
        w &= ~1; h &= ~1;
        if (w < 2) w = 2;
        if (h < 2) h = 2;
    }

    if (d->sws_w != sw || d->sws_h != sh || d->sws_fmt != d->frame->format) {
        d->sws = sws_getCachedContext(d->sws, sw, sh, d->frame->format, w, h, AV_PIX_FMT_RGBA,
                                      SWS_BILINEAR, NULL, NULL, NULL);
        d->sws_w = sw; d->sws_h = sh; d->sws_fmt = d->frame->format;
    }
    if (!d->sws) return;
    uint8_t *dst = acquire(ud, w, h);
    if (!dst) return;
    uint8_t *dstp[4]  = { dst, NULL, NULL, NULL };
    int      dstst[4] = { w * 4, 0, 0, 0 };
    sws_scale(d->sws, (const uint8_t * const *)d->frame->data, d->frame->linesize, 0, sh, dstp, dstst);
    commit(ud, w, h);
}

int tri_vdec_feed(tri_vdec *d, const uint8_t *data, int len,
                  uint8_t *(*acquire)(void *ud, int w, int h),
                  void (*commit)(void *ud, int w, int h), void *ud) {
    if (!d || !data || len <= 0) return 0;
    d->pkt->data = (uint8_t *)data;
    d->pkt->size = len;
    if (avcodec_send_packet(d->ctx, d->pkt) < 0) return -1;
    int n = 0;
    for (;;) {
        int r = avcodec_receive_frame(d->ctx, d->frame);
        if (r == AVERROR(EAGAIN) || r == AVERROR_EOF) break;
        if (r < 0) return -1;
        emit_frame(d, acquire, commit, ud);
        av_frame_unref(d->frame);
        n++;
    }
    return n;
}

void tri_vdec_free(tri_vdec *d) {
    if (!d) return;
    if (d->sws)   sws_freeContext(d->sws);
    if (d->frame) av_frame_free(&d->frame);
    if (d->pkt)   av_packet_free(&d->pkt);
    if (d->ctx)   avcodec_free_context(&d->ctx);
    free(d);
}

#else

tri_vdec *tri_vdec_new(const char *codec) { (void)codec; return NULL; }
int tri_vdec_feed(tri_vdec *d, const uint8_t *data, int len,
                  uint8_t *(*acquire)(void *, int, int),
                  void (*commit)(void *, int, int), void *ud) {
    (void)d; (void)data; (void)len; (void)acquire; (void)commit; (void)ud; return -1;
}
void tri_vdec_free(tri_vdec *d) { (void)d; }

#endif

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#define VA_IN_CAP  16
#define VA_OUT_CAP  8

struct tri_vdec_async {
    tri_vdec *dec;
    pthread_t thread; int threaded;
    pthread_mutex_t lock; pthread_cond_t cond;
    int stop, fatal;
    int wake_r, wake_w;
    struct { uint8_t *data; int len; } in[VA_IN_CAP];
    int in_head, in_count;
    struct { uint8_t *rgba; int w, h; } out[VA_OUT_CAP];
    int out_head, out_count;
    uint8_t *pending; int pend_w, pend_h;
};

static void va_setnb(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

static uint8_t *va_acquire(void *ud, int w, int h) {
    struct tri_vdec_async *d = ud;
    free(d->pending);
    d->pending = malloc((size_t)w * h * 4);
    d->pend_w = w; d->pend_h = h;
    return d->pending;
}
static void va_commit(void *ud, int w, int h) {
    struct tri_vdec_async *d = ud;
    if (!d->pending) return;
    pthread_mutex_lock(&d->lock);
    if (d->out_count >= VA_OUT_CAP) {
        free(d->out[d->out_head].rgba);
        d->out_head = (d->out_head + 1) % VA_OUT_CAP; d->out_count--;
    }
    int slot = (d->out_head + d->out_count) % VA_OUT_CAP;
    d->out[slot].rgba = d->pending; d->out[slot].w = w; d->out[slot].h = h; d->out_count++;
    pthread_mutex_unlock(&d->lock);
    d->pending = NULL;
    char b = 1; ssize_t wr = write(d->wake_w, &b, 1); (void)wr;
}
static void *va_worker(void *ud) {
    struct tri_vdec_async *d = ud;
    for (;;) {
        pthread_mutex_lock(&d->lock);
        while (d->in_count == 0 && !d->stop) pthread_cond_wait(&d->cond, &d->lock);
        if (d->in_count == 0 && d->stop) { pthread_mutex_unlock(&d->lock); break; }
        uint8_t *data = d->in[d->in_head].data; int len = d->in[d->in_head].len;
        d->in_head = (d->in_head + 1) % VA_IN_CAP; d->in_count--;
        pthread_mutex_unlock(&d->lock);
        int r = tri_vdec_feed(d->dec, data, len, va_acquire, va_commit, d);
        free(data);
        if (r < 0) {
            pthread_mutex_lock(&d->lock); d->fatal = 1; pthread_mutex_unlock(&d->lock);
            char b = 1; ssize_t wr = write(d->wake_w, &b, 1); (void)wr;
        }
    }
    return NULL;
}

tri_vdec_async *tri_vdec_async_new(const char *codec) {
    tri_vdec *dec = tri_vdec_new(codec);
    if (!dec) return NULL;
    struct tri_vdec_async *d = calloc(1, sizeof *d);
    if (!d) { tri_vdec_free(dec); return NULL; }
    d->wake_r = d->wake_w = -1;
    int fds[2];
    if (pipe(fds) != 0) { tri_vdec_free(dec); free(d); return NULL; }
    d->wake_r = fds[0]; d->wake_w = fds[1]; va_setnb(d->wake_r); va_setnb(d->wake_w);
    if (pthread_mutex_init(&d->lock, NULL) != 0) goto fail;
    if (pthread_cond_init(&d->cond, NULL) != 0) { pthread_mutex_destroy(&d->lock); goto fail; }
    d->dec = dec;
    if (pthread_create(&d->thread, NULL, va_worker, d) != 0) {
        pthread_cond_destroy(&d->cond); pthread_mutex_destroy(&d->lock); goto fail;
    }
    d->threaded = 1;
    return d;
fail:
    close(d->wake_r); close(d->wake_w); tri_vdec_free(dec); free(d); return NULL;
}

int tri_vdec_async_feed(tri_vdec_async *d, const uint8_t *data, int len) {
    if (!d || len <= 0) return d ? 0 : -1;
    pthread_mutex_lock(&d->lock);
    if (d->fatal) { pthread_mutex_unlock(&d->lock); return -1; }
    uint8_t *copy = malloc((size_t)len);
    if (!copy) { pthread_mutex_unlock(&d->lock); return 0; }
    memcpy(copy, data, (size_t)len);
    if (d->in_count >= VA_IN_CAP) {
        free(d->in[d->in_head].data);
        d->in_head = (d->in_head + 1) % VA_IN_CAP; d->in_count--;
    }
    int slot = (d->in_head + d->in_count) % VA_IN_CAP;
    d->in[slot].data = copy; d->in[slot].len = len; d->in_count++;
    pthread_cond_signal(&d->cond);
    pthread_mutex_unlock(&d->lock);
    return 0;
}

int tri_vdec_async_fd(tri_vdec_async *d) { return d ? d->wake_r : -1; }

void tri_vdec_async_drain(tri_vdec_async *d, void (*publish)(void *, int, int, const uint8_t *), void *ud) {
    if (!d) return;
    char sink[64]; while (read(d->wake_r, sink, sizeof sink) > 0) { }
    for (;;) {
        pthread_mutex_lock(&d->lock);
        if (d->out_count == 0) { pthread_mutex_unlock(&d->lock); break; }
        uint8_t *rgba = d->out[d->out_head].rgba; int w = d->out[d->out_head].w, h = d->out[d->out_head].h;
        d->out_head = (d->out_head + 1) % VA_OUT_CAP; d->out_count--;
        pthread_mutex_unlock(&d->lock);
        if (publish) publish(ud, w, h, rgba);
        free(rgba);
    }
}

int tri_vdec_async_fatal(tri_vdec_async *d) {
    if (!d) return 1;
    pthread_mutex_lock(&d->lock); int f = d->fatal; pthread_mutex_unlock(&d->lock);
    return f;
}

void tri_vdec_async_free(tri_vdec_async *d) {
    if (!d) return;
    if (d->threaded) {
        pthread_mutex_lock(&d->lock); d->stop = 1; pthread_cond_signal(&d->cond); pthread_mutex_unlock(&d->lock);
        pthread_join(d->thread, NULL);
        pthread_cond_destroy(&d->cond); pthread_mutex_destroy(&d->lock);
    }
    if (d->dec) tri_vdec_free(d->dec);
    free(d->pending);
    while (d->in_count > 0)  { free(d->in[d->in_head].data);  d->in_head  = (d->in_head + 1) % VA_IN_CAP;  d->in_count--; }
    while (d->out_count > 0) { free(d->out[d->out_head].rgba); d->out_head = (d->out_head + 1) % VA_OUT_CAP; d->out_count--; }
    if (d->wake_r >= 0) close(d->wake_r);
    if (d->wake_w >= 0) close(d->wake_w);
    free(d);
}
