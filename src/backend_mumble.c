#include "trichat.h"
#include "util.h"
#include "resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <opus.h>

enum { MT_VERSION = 0, MT_UDPTUNNEL = 1, MT_AUTHENTICATE = 2, MT_PING = 3,
       MT_REJECT = 4, MT_SERVERSYNC = 5, MT_CHANNELREMOVE = 6, MT_CHANNELSTATE = 7,
       MT_USERREMOVE = 8, MT_USERSTATE = 9, MT_TEXTMESSAGE = 11, MT_CODECVERSION = 21 };

enum { ST_RESOLVING, ST_CONNECTING, ST_TLS_HS, ST_ONLINE };

#define SAMPLE_RATE 48000
#define FRAME_SAMPLES 960
#define MAX_CHANS 512

typedef struct { uint32_t id, parent; char name[128]; int known; } mch_t;
typedef struct { uint32_t session, channel_id; char name[128]; int talking; int muted, deafened; double last_voice; char roster_chan[128]; } muser_t;
typedef struct { uint32_t session; OpusDecoder *dec; tri_audio_sink *sink; } mdec_t;
#define MAX_USERS 256

typedef struct {
    char host[256], port[8], user[128], pass[160], joinchan[128];
    int state;
    tri_resolve *resolve;
    uint32_t session;
    uint32_t self_channel;
    int self_mute, self_deaf;
    int split_audio;
    mch_t chans[MAX_CHANS];
    int nchans;
    muser_t users[MAX_USERS];
    int nusers;

    uint8_t rbuf[262144];
    size_t  rlen;
    double  last_ping;

    int playing;
    int16_t *pcm;
    size_t pcm_n, pcm_pos;
    uint32_t aseq;
    double play_start;
    OpusEncoder *enc;

    tri_audio_source *mic;
    int16_t mic_acc[FRAME_SAMPLES]; int mic_n;
    uint32_t micseq;

    mdec_t decoders[MAX_USERS];
    int ndec;
    tri_audio_sink *play_out;

    int recording; double rec_start; char rec_dir[400];
    struct { uint32_t session; FILE *f; long samples; } rec[MAX_USERS];
    int nrec;

    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
} mum_priv;

static double now_s(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

static void emit(account_t *a, tri_event_kind k, const char *target, const char *text) {
    tri_event_t ev = { k, tri_account_key(a), target, text, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static size_t pb_varint(uint8_t *b, uint64_t v) {
    size_t n = 0;
    do { uint8_t x = v & 0x7f; v >>= 7; if (v) x |= 0x80; b[n++] = x; } while (v);
    return n;
}
static size_t pb_u32(uint8_t *b, int field, uint32_t v) {
    size_t n = pb_varint(b, (uint64_t)field << 3 | 0);
    return n + pb_varint(b + n, v);
}
static size_t pb_str(uint8_t *b, int field, const char *s) {
    size_t L = strlen(s), n = pb_varint(b, (uint64_t)field << 3 | 2);
    n += pb_varint(b + n, L);
    memcpy(b + n, s, L);
    return n + L;
}

static size_t mvar(uint8_t *b, uint64_t i) {
    if (i < 0x80)           { b[0] = i; return 1; }
    if (i < 0x4000)         { b[0] = (i >> 8) | 0x80;  b[1] = i & 0xFF; return 2; }
    if (i < 0x200000)       { b[0] = (i >> 16) | 0xC0; b[1] = (i >> 8) & 0xFF; b[2] = i & 0xFF; return 3; }
    if (i < 0x10000000)     { b[0] = (i >> 24) | 0xE0; b[1] = (i >> 16) & 0xFF; b[2] = (i >> 8) & 0xFF; b[3] = i & 0xFF; return 4; }
    if (i < 0x100000000ULL) { b[0] = 0xF0; b[1] = (i >> 24) & 0xFF; b[2] = (i >> 16) & 0xFF; b[3] = (i >> 8) & 0xFF; b[4] = i & 0xFF; return 5; }
    b[0] = 0xF4; for (int k = 0; k < 8; k++) b[1 + k] = (i >> (56 - 8 * k)) & 0xFF; return 9;
}

static uint64_t rd_varint(const uint8_t **p, const uint8_t *end) {
    uint64_t v = 0; int sh = 0;
    while (*p < end) { uint8_t x = *(*p)++; v |= (uint64_t)(x & 0x7f) << sh; if (!(x & 0x80)) break; sh += 7; }
    return v;
}

static uint64_t rd_mvar(const uint8_t **pp, const uint8_t *end) {
    if (*pp >= end) return 0;
    uint8_t v = *(*pp)++;
    if ((v & 0x80) == 0) return v & 0x7F;
    if ((v & 0xC0) == 0x80) { uint64_t r = (uint64_t)(v & 0x3F) << 8; if (*pp < end) r |= *(*pp)++; return r; }
    if ((v & 0xE0) == 0xC0) { uint64_t r = (uint64_t)(v & 0x1F) << 16; for (int k = 0; k < 2 && *pp < end; k++) r |= (uint64_t)*(*pp)++ << (8 - 8 * k); return r; }
    if ((v & 0xF0) == 0xE0) { uint64_t r = (uint64_t)(v & 0x0F) << 24; for (int k = 0; k < 3 && *pp < end; k++) r |= (uint64_t)*(*pp)++ << (16 - 8 * k); return r; }
    if ((v & 0xFC) == 0xF0) { uint64_t r = 0; for (int k = 0; k < 4 && *pp < end; k++) r = (r << 8) | *(*pp)++; return r; }
    if ((v & 0xFC) == 0xF4) { uint64_t r = 0; for (int k = 0; k < 8 && *pp < end; k++) r = (r << 8) | *(*pp)++; return r; }
    return 0;
}

static int mum_send(account_t *a, int type, const uint8_t *payload, size_t n) {
    mum_priv *p = tri_account_priv(a);
    uint8_t hdr[6] = { type >> 8, type & 0xff, n >> 24, n >> 16, n >> 8, n & 0xff };

    static uint8_t out[270000];
    if (n + 6 > sizeof out) return tri_set_error("mumble: message too large (%zu)", n);
    memcpy(out, hdr, 6);
    memcpy(out + 6, payload, n);
    if (wolfSSL_write(p->ssl, out, n + 6) != (int)(n + 6))
        return tri_set_error("mumble: TLS write failed on '%s'", tri_account_name(a));
    return 0;
}

static void mum_teardown(account_t *a, const char *why);
static void mum_mic_stop(account_t *a);

static const char *img_ctype(const char *path) {
    const char *d = strrchr(path, '.'); if (!d) return NULL;
    if (!strcasecmp(d, ".png")) return "image/png";
    if (!strcasecmp(d, ".jpg") || !strcasecmp(d, ".jpeg")) return "image/jpeg";
    if (!strcasecmp(d, ".gif")) return "image/gif";
    if (!strcasecmp(d, ".webp")) return "image/webp";
    if (!strcasecmp(d, ".bmp")) return "image/bmp";
    return NULL;
}
static char *mum_html_to_text(const char *html) {
    size_t cap = strlen(html) + 64;
    char *out = malloc(cap); if (!out) return NULL;
    size_t o = 0;
    for (const char *p = html; *p; ) {
        if (*p == '<') {
            const char *attr = NULL;
            if (!strncasecmp(p, "<img", 4)) attr = "src=";
            else if (!strncasecmp(p, "<a ", 3)) attr = "href=";
            const char *gt = strchr(p, '>'); if (!gt) break;
            if (attr) {
                const char *q = p;
                while ((q = strstr(q, attr)) && q < gt) {
                    if (q == p || q[-1] == ' ' || q[-1] == '\t') break;
                    q += strlen(attr);
                }
                if (q && q < gt) {
                    q += strlen(attr);
                    char qt = *q;
                    const char *e = (qt == '"' || qt == '\'') ? strchr(q + 1, qt) : NULL;
                    if (e) { size_t vl = (size_t)(e - (q + 1));
                             if (o + vl + 2 < cap) { memcpy(out + o, q + 1, vl); o += vl; out[o++] = ' '; } }
                }
            }
            p = gt + 1; continue;
        }
        if (o + 1 >= cap) break;
        out[o++] = *p++;
    }
    out[o] = '\0';
    return out;
}

static mch_t *chan_by_id(mum_priv *p, uint32_t id) {
    for (int i = 0; i < p->nchans; i++) if (p->chans[i].known && p->chans[i].id == id) return &p->chans[i];
    return NULL;
}
static mch_t *chan_by_name(mum_priv *p, const char *name) {
    for (int i = 0; i < p->nchans; i++) if (p->chans[i].known && !strcasecmp(p->chans[i].name, name)) return &p->chans[i];
    return NULL;
}
static muser_t *user_find(mum_priv *p, uint32_t session) {
    for (int i = 0; i < p->nusers; i++) if (p->users[i].session == session) return &p->users[i];
    return NULL;
}
static const char *user_name(mum_priv *p, uint32_t session) {
    muser_t *u = user_find(p, session);
    return u ? u->name : NULL;
}
static muser_t *user_find_by_name(mum_priv *p, const char *name) {
    for (int i = 0; i < p->nusers; i++) if (!strcmp(p->users[i].name, name)) return &p->users[i];
    return NULL;
}
static muser_t *user_get(mum_priv *p, uint32_t session) {
    muser_t *u = user_find(p, session);
    if (u) return u;
    if (p->nusers >= MAX_USERS) return NULL;
    u = &p->users[p->nusers++];
    memset(u, 0, sizeof *u);
    u->session = session;
    return u;
}

static void roster_push(account_t *a, muser_t *u) {
    mum_priv *p = tri_account_priv(a);
    mch_t *c = chan_by_id(p, u->channel_id);
    const char *chan = c ? c->name : "(channel)";
    const char *name = u->name[0] ? u->name : "(user)";

    if (u->roster_chan[0] && strcmp(u->roster_chan, chan))
        tri_roster_remove_from(a, u->roster_chan, name);
    snprintf(u->roster_chan, sizeof u->roster_chan, "%s", chan);
    int mask = (u->talking ? TRI_VOICE_TALKING : 0) | (u->muted ? TRI_VOICE_MUTED : 0) | (u->deafened ? TRI_VOICE_DEAF : 0);
    tri_roster_upsert(a, chan, name, mask);
}

static OpusDecoder *decoder_for(mum_priv *p, uint32_t session) {
    for (int i = 0; i < p->ndec; i++) if (p->decoders[i].session == session) return p->decoders[i].dec;
    if (p->ndec >= MAX_USERS) return NULL;
    int err; OpusDecoder *d = opus_decoder_create(SAMPLE_RATE, 1, &err);
    if (!d) return NULL;
    p->decoders[p->ndec].session = session; p->decoders[p->ndec].dec = d; p->ndec++;
    return d;
}

static FILE *wav_open(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return NULL;
    unsigned rate = 48000, byterate = rate * 2, zero = 0, sixteen = 16;
    unsigned short fmt = 1, ch = 1, blockalign = 2, bits = 16;
    fwrite("RIFF", 1, 4, f); fwrite(&zero, 4, 1, f); fwrite("WAVE", 1, 4, f);
    fwrite("fmt ", 1, 4, f); fwrite(&sixteen, 4, 1, f);
    fwrite(&fmt, 2, 1, f); fwrite(&ch, 2, 1, f); fwrite(&rate, 4, 1, f);
    fwrite(&byterate, 4, 1, f); fwrite(&blockalign, 2, 1, f); fwrite(&bits, 2, 1, f);
    fwrite("data", 1, 4, f); fwrite(&zero, 4, 1, f);
    return f;
}
static void wav_close(FILE *f, long samples) {
    if (!f) return;
    unsigned data = (unsigned)(samples * 2), riff = 36 + data;
    fseek(f, 4, SEEK_SET);  fwrite(&riff, 4, 1, f);
    fseek(f, 40, SEEK_SET); fwrite(&data, 4, 1, f);
    fclose(f);
}

static void mk_dirs(const char *path) {
    char tmp[420]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char *s = tmp + 1; *s; s++) if (*s == '/') { *s = '\0'; mkdir(tmp, 0700); *s = '/'; }
    mkdir(tmp, 0700);
}
static int rec_track(account_t *a, mum_priv *p, uint32_t session, const char *name) {
    for (int i = 0; i < p->nrec; i++) if (p->rec[i].session == session) return i;
    if (p->nrec >= MAX_USERS) return -1;
    char safe[128], path[600]; int j = 0;
    for (const char *s = name && name[0] ? name : "unknown"; *s && j < 120; s++)
        safe[j++] = (*s == '/' || *s == '\\' || (unsigned char)*s < 0x20) ? '_' : *s;
    safe[j] = '\0';
    snprintf(path, sizeof path, "%s/%u-%s.wav", p->rec_dir, session, safe);
    FILE *f = wav_open(path);
    if (!f) { char e[700]; snprintf(e, sizeof e, "mumble: cannot open recording %s", path); emit(a, TRI_EV_ERROR, NULL, e); return -1; }
    int i = p->nrec++;
    p->rec[i].session = session; p->rec[i].f = f; p->rec[i].samples = 0;
    return i;
}
static void rec_stop(account_t *a, mum_priv *p) {
    for (int i = 0; i < p->nrec; i++) wav_close(p->rec[i].f, p->rec[i].samples);
    p->nrec = 0; p->recording = 0;
    (void)a;
}

static tri_audio_sink *voice_sink(account_t *a, mum_priv *p, uint32_t session, const char *who) {
    tri_core *c = tri_account_core(a);
    if (!p->split_audio) {
        if (!p->play_out) {
            p->play_out = tri_audio_open(c);
            if (!p->play_out) { char e[220]; snprintf(e, sizeof e, "mumble: audio output failed: %s", tri_last_error()); emit(a, TRI_EV_ERROR, NULL, e); return NULL; }
            char m[160]; snprintf(m, sizeof m, "receiving voice%s%s", who ? " from " : "", who ? who : "");
            emit(a, TRI_EV_STATUS, NULL, m);
        }
        return p->play_out;
    }
    for (int i = 0; i < p->ndec; i++) if (p->decoders[i].session == session) {
        if (!p->decoders[i].sink) {
            char nm[160]; snprintf(nm, sizeof nm, "Trichat: %s", who && who[0] ? who : "speaker");
            p->decoders[i].sink = tri_audio_open_named(c, nm);
            if (!p->decoders[i].sink) { char e[220]; snprintf(e, sizeof e, "mumble: audio output failed: %s", tri_last_error()); emit(a, TRI_EV_ERROR, NULL, e); return NULL; }
            char m[200]; snprintf(m, sizeof m, "receiving voice from %s (own stream)", who && who[0] ? who : "a speaker");
            emit(a, TRI_EV_STATUS, NULL, m);
        }
        return p->decoders[i].sink;
    }
    return NULL;
}

static void play_voice(account_t *a, uint32_t session, const uint8_t *opus, int olen) {
    mum_priv *p = tri_account_priv(a);
    muser_t *u = user_get(p, session);
    if (u) { u->last_voice = now_s(); if (!u->talking) { u->talking = 1; roster_push(a, u); } }
    if (p->self_deaf) return;
    if (u && u->name[0] && tri_user_ignored(a, u->name)) return;
    OpusDecoder *dec = decoder_for(p, session);
    if (!dec) return;
    int16_t pcm[5760];
    int samples = opus_decode(dec, opus, olen, pcm, 5760, 0);
    if (samples <= 0) return;
    tri_audio_sink *sink = voice_sink(a, p, session, u ? u->name : NULL);
    if (sink) tri_audio_write(sink, pcm, samples);

    if (p->recording && samples > 0) {
        int ri = rec_track(a, p, session, u ? u->name : NULL);
        if (ri >= 0) {
            long want = (long)((now_s() - p->rec_start) * 48000) - samples;
            for (long pad = want - p->rec[ri].samples; pad > 0; ) {
                int16_t z[1024] = {0}; long chunk = pad > 1024 ? 1024 : pad;
                fwrite(z, 2, chunk, p->rec[ri].f); p->rec[ri].samples += chunk; pad -= chunk;
            }
            fwrite(pcm, 2, samples, p->rec[ri].f); p->rec[ri].samples += samples;
        }
    }
}

static int mum_record(account_t *a, const char *dir) {
    mum_priv *p = tri_account_priv(a);
    if (!p) return tri_set_error("mumble: not connected");
    if (dir && dir[0]) {
        if (p->recording) rec_stop(a, p);
        mk_dirs(dir);
        snprintf(p->rec_dir, sizeof p->rec_dir, "%s", dir);
        p->rec_start = now_s(); p->nrec = 0; p->recording = 1;
        emit(a, TRI_EV_STATUS, NULL, "recording started (one WAV per speaker)");
    } else if (p->recording) {
        rec_stop(a, p);
        emit(a, TRI_EV_STATUS, NULL, "recording stopped");
    }
    return 0;
}

static void send_version(account_t *a) {
    uint8_t b[128]; size_t n = 0;
    n += pb_u32(b + n, 1, (1 << 16) | (4 << 8) | 0);
    n += pb_varint(b + n, (uint64_t)5 << 3 | 0);
    n += pb_varint(b + n, ((uint64_t)1 << 48) | ((uint64_t)4 << 32));
    n += pb_str(b + n, 2, "Trichat");
    n += pb_str(b + n, 3, "Linux");
    mum_send(a, MT_VERSION, b, n);
}
static void send_auth(account_t *a) {
    mum_priv *p = tri_account_priv(a);
    uint8_t b[512]; size_t n = 0;
    n += pb_str(b + n, 1, p->user);
    if (p->pass[0]) n += pb_str(b + n, 2, p->pass);
    n += pb_u32(b + n, 5, 1);
    mum_send(a, MT_AUTHENTICATE, b, n);
}
static void send_ping(account_t *a) {
    uint8_t b[16]; size_t n = pb_varint(b, (uint64_t)1 << 3 | 0);
    n += pb_varint(b + n, (uint64_t)(now_s() * 1000));
    mum_send(a, MT_PING, b, n);
}

static int parse_url(mum_priv *p, const char *url) {
    char buf[600]; snprintf(buf, sizeof buf, "%s", url ? url : "");
    char *qs = strchr(buf, '?');
    if (qs) { p->split_audio = (strstr(qs, "split") != NULL); *qs = '\0'; }
    char *s = buf;
    if (strncmp(s, "mumble://", 9)) return tri_set_error("mumble: config must start with mumble:// (got '%s')", url);
    s += 9;
    char *slash = strchr(s, '/');
    if (slash) { *slash++ = '\0'; snprintf(p->joinchan, sizeof p->joinchan, "%s", slash); }
    char *at = strrchr(s, '@');
    if (at) {
        *at = '\0';
        char *colon = strchr(s, ':');
        if (colon) { *colon = '\0'; snprintf(p->pass, sizeof p->pass, "%s", colon + 1); }
        snprintf(p->user, sizeof p->user, "%s", s);
        s = at + 1;
    }
    if (!*s) return tri_set_error("mumble: no host in config '%s'", url);
    char *pcolon = strchr(s, ':');
    if (pcolon) { *pcolon = '\0'; snprintf(p->port, sizeof p->port, "%s", pcolon + 1); }
    else snprintf(p->port, sizeof p->port, "64738");
    snprintf(p->host, sizeof p->host, "%s", s);
    if (!p->user[0]) snprintf(p->user, sizeof p->user, "Trichat");
    return 0;
}

static int tls_check_pin(account_t *a, const char *host) {
    if (tri_account_insecure(a)) return 0;
    mum_priv *p = tri_account_priv(a);
    WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(p->ssl);
    if (!cert) return 0;
    int derSz = 0; const unsigned char *der = wolfSSL_X509_get_der(cert, &derSz);
    unsigned char h[32]; int hashed = (der && derSz > 0) ? wc_Sha256Hash(der, (word32)derSz, h) : -1;
    wolfSSL_X509_free(cert);
    if (hashed != 0) return 0;
    char fp[65]; for (int i = 0; i < 32; i++) snprintf(fp + i * 2, 3, "%02x", h[i]);
    tri_core *c = tri_account_core(a);
    int r = tri_tls_pin_check(c, host, fp);
    if (r == TRI_PIN_MISMATCH)
        return tri_set_error("mumble: TLS certificate for %s changed since first use (possible MITM) - add ?insecure to override", host);
    if (r == TRI_PIN_NEW) { tri_tls_pin_store(c, host, fp); emit(a, TRI_EV_STATUS, NULL, "pinned server TLS certificate (first use)"); }
    return 0;
}

static void tls_pump(account_t *a) {
    mum_priv *p = tri_account_priv(a);
    if (wolfSSL_connect(p->ssl) == WOLFSSL_SUCCESS) {
        tri_account_set_write_interest(a, 0);
        if (tls_check_pin(a, p->host) != 0) { emit(a, TRI_EV_ERROR, NULL, tri_last_error());
                                              char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                                              mum_teardown(a, NULL); tri_account_notify_failed(a, m); return; }
        p->state = ST_ONLINE;
        emit(a, TRI_EV_STATUS, NULL, "TLS up, authenticating");
        send_version(a);
        send_auth(a);
        p->last_ping = now_s();
        return;
    }
    int err = wolfSSL_get_error(p->ssl, 0);
    if (err == WOLFSSL_ERROR_WANT_WRITE) { tri_account_set_write_interest(a, 1); return; }
    if (err == WOLFSSL_ERROR_WANT_READ)  { tri_account_set_write_interest(a, 0); return; }
    char e[80]; wolfSSL_ERR_error_string(err, e);
    tri_set_error("mumble: TLS handshake with %s failed: %s", p->host, e);
    emit(a, TRI_EV_ERROR, NULL, tri_last_error());
    mum_teardown(a, NULL);
}

static void mum_resolved(void *ud, int ok, const struct sockaddr *sa, socklen_t salen,
                         int socktype, int proto, const char *err) {
    account_t *a = ud;
    mum_priv *p = tri_account_priv(a);
    if (!p) return;
    p->resolve = NULL;
    if (!ok) {
        tri_set_error("mumble: cannot resolve %s:%s: %s", p->host, p->port, err);
        emit(a, TRI_EV_ERROR, NULL, tri_last_error()); mum_teardown(a, NULL); return;
    }
    int fd = socket(sa->sa_family, socktype, proto);
    if (fd < 0) { tri_set_error("mumble: socket() failed: %s", strerror(errno));
                  emit(a, TRI_EV_ERROR, NULL, tri_last_error()); mum_teardown(a, NULL); return; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int rc = connect(fd, sa, salen);
    if (rc != 0 && errno != EINPROGRESS) {
        tri_set_error("mumble: connect to %s:%s failed: %s", p->host, p->port, strerror(errno));
        emit(a, TRI_EV_ERROR, NULL, tri_last_error()); close(fd); mum_teardown(a, NULL); return;
    }
    tri_account_set_fd(a, fd);
    p->state = ST_CONNECTING;
    tri_account_set_write_interest(a, 1);

    static int inited = 0;
    if (!inited) { wolfSSL_Init(); inited = 1; }
    p->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!p->ctx) { tri_set_error("mumble: wolfSSL_CTX_new failed");
                   emit(a, TRI_EV_ERROR, NULL, tri_last_error()); mum_teardown(a, NULL); return; }
    wolfSSL_CTX_set_verify(p->ctx, WOLFSSL_VERIFY_NONE, NULL);
    p->ssl = wolfSSL_new(p->ctx);
    wolfSSL_set_fd(p->ssl, fd);
    emit(a, TRI_EV_STATUS, NULL, "connecting...");
}

static int mum_connect(account_t *a) {
    mum_priv *p = calloc(1, sizeof *p);
    if (!p) return tri_set_error("mumble: out of memory");
    if (parse_url(p, tri_account_config(a)) != 0) { free(p); return -1; }
    tri_account_set_priv(a, p);
    p->state = ST_RESOLVING;
    p->resolve = tri_resolve_start(tri_account_core(a), p->host, p->port, SOCK_STREAM, mum_resolved, a);
    if (!p->resolve) { free(p); tri_account_set_priv(a, NULL); return -1; }
    emit(a, TRI_EV_STATUS, NULL, "resolving...");
    return 0;
}

static void mum_teardown(account_t *a, const char *why) {
    mum_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->resolve) { tri_resolve_cancel(p->resolve); p->resolve = NULL; }
    int fd = tri_account_fd(a);
    if (fd >= 0) {
        if (p->ssl) { if (p->state == ST_ONLINE) wolfSSL_shutdown(p->ssl); wolfSSL_free(p->ssl); }
        if (p->ctx) wolfSSL_CTX_free(p->ctx);
        close(fd);
    }
    if (p->recording) rec_stop(a, p);
    mum_mic_stop(a);
    if (p->enc) opus_encoder_destroy(p->enc);
    for (int i = 0; i < p->ndec; i++) { opus_decoder_destroy(p->decoders[i].dec);
                                        if (p->decoders[i].sink) tri_audio_close(p->decoders[i].sink); }
    if (p->play_out) tri_audio_close(p->play_out);
    free(p->pcm);
    tri_roster_clear_account(a);
    tri_chantree_clear_account(a);
    tri_account_set_write_interest(a, 0);
    if (why) emit(a, TRI_EV_STATUS, NULL, why);
    free(p);
    tri_account_set_priv(a, NULL);
    tri_account_set_fd(a, -1);
}

static void mum_disconnect(account_t *a) { mum_teardown(a, tri_account_priv(a) ? "disconnected" : NULL); }

static void handle_message(account_t *a, int type, const uint8_t *b, size_t n) {
    mum_priv *p = tri_account_priv(a);
    const uint8_t *end = b + n;

    if (type == MT_SERVERSYNC) {
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (f == 1 && wt == 0) p->session = rd_varint(&b, end);
            else if (wt == 0) rd_varint(&b, end);
            else if (wt == 2) { uint64_t L = rd_varint(&b, end); b += L; }
            else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        tri_account_set_state(a, TRI_CS_ONLINE);
        emit(a, TRI_EV_STATUS, NULL, "logged in");
        if (p->joinchan[0]) { mch_t *c = chan_by_name(p, p->joinchan); if (c) { uint8_t m[32]; size_t mn = pb_u32(m, 1, p->session); mn += pb_u32(m + mn, 5, c->id); mum_send(a, MT_USERSTATE, m, mn); } }
        return;
    }
    if (type == MT_CHANNELSTATE) {
        uint32_t id = 0, parent = 0; char name[128] = ""; int have_id = 0, have_parent = 0, have_name = 0;
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (wt == 0) { uint64_t v = rd_varint(&b, end); if (f == 1) { id = v; have_id = 1; } else if (f == 2) { parent = v; have_parent = 1; } }
            else if (wt == 2) { uint64_t L = rd_varint(&b, end); if (f == 3 && L < sizeof name) { memcpy(name, b, L); name[L] = 0; have_name = 1; } b += L; }
            else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        if (have_id) {
            mch_t *c = chan_by_id(p, id);
            if (!c && p->nchans < MAX_CHANS) c = &p->chans[p->nchans++];
            if (c) { c->known = 1; c->id = id; if (have_parent) c->parent = parent; if (have_name) snprintf(c->name, sizeof c->name, "%s", name); }

            tri_chantree_upsert(a, id, have_parent ? parent : (unsigned)-1, have_name ? name : NULL);
        }
        return;
    }
    if (type == MT_CHANNELREMOVE) {
        uint32_t id = 0; int have = 0;
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (wt == 0) { uint64_t v = rd_varint(&b, end); if (f == 1) { id = v; have = 1; } }
            else if (wt == 2) { uint64_t L = rd_varint(&b, end); b += L; }
            else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        if (have) {
            for (int i = 0; i < p->nchans; i++) if (p->chans[i].id == id) { p->chans[i] = p->chans[--p->nchans]; break; }
            tri_chantree_remove(a, id);
        }
        return;
    }
    if (type == MT_USERSTATE) {
        uint32_t session = 0, channel = 0; int have_chan = 0, have_session = 0; char uname[128] = "";
        int mute = 0, deaf = 0, supp = 0, smute = 0, sdeaf = 0;
        int h_mute = 0, h_deaf = 0, h_supp = 0, h_smute = 0, h_sdeaf = 0;
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (wt == 0) { uint64_t v = rd_varint(&b, end);
                if (f == 1) { session = v; have_session = 1; } else if (f == 5) { channel = v; have_chan = 1; }
                else if (f == 6) { mute = v; h_mute = 1; } else if (f == 7) { deaf = v; h_deaf = 1; }
                else if (f == 8) { supp = v; h_supp = 1; } else if (f == 9) { smute = v; h_smute = 1; }
                else if (f == 10) { sdeaf = v; h_sdeaf = 1; } }
            else if (wt == 2) { uint64_t L = rd_varint(&b, end); if (f == 3 && L < sizeof uname) { memcpy(uname, b, L); uname[L] = 0; } b += L; }
            else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        if (!have_session) return;
        muser_t *u = user_get(p, session);
        if (!u) return;
        if (uname[0]) snprintf(u->name, sizeof u->name, "%s", uname);
        if (have_chan) u->channel_id = channel;

        if (h_mute || h_supp || h_smute) u->muted = (h_mute && mute) || (h_supp && supp) || (h_smute && smute);
        if (h_deaf || h_sdeaf) u->deafened = (h_deaf && deaf) || (h_sdeaf && sdeaf);
        if (session == p->session) {
            if (h_smute) p->self_mute = smute;
            if (h_sdeaf) p->self_deaf = sdeaf;
        }
        roster_push(a, u);
        if (session == p->session && have_chan) {
            p->self_channel = channel;
            mch_t *c = chan_by_id(p, channel);
            char t[160]; snprintf(t, sizeof t, "you are in: %s", c ? c->name : "(channel)");
            emit(a, TRI_EV_STATUS, NULL, t);
        }
        return;
    }
    if (type == MT_USERREMOVE) {
        uint32_t session = 0;
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (wt == 0) { uint64_t v = rd_varint(&b, end); if (f == 1) session = v; }
            else if (wt == 2) { uint64_t L = rd_varint(&b, end); b += L; }
            else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        muser_t *u = user_find(p, session);
        if (u) { tri_roster_remove(a, u->name[0] ? u->name : "(user)"); *u = p->users[--p->nusers]; }
        for (int i = 0; i < p->ndec; i++) if (p->decoders[i].session == session) {
            opus_decoder_destroy(p->decoders[i].dec);
            if (p->decoders[i].sink) tri_audio_close(p->decoders[i].sink);
            p->decoders[i] = p->decoders[--p->ndec];
            break;
        }
        return;
    }
    if (type == MT_TEXTMESSAGE) {
        char *msg = NULL; uint32_t actor = 0, channel = 0; int have_chan = 0;
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (wt == 0) { uint64_t v = rd_varint(&b, end); if (f == 1) actor = v; else if (f == 3 && !have_chan) { channel = v; have_chan = 1; } }
            else if (wt == 2) { uint64_t L = rd_varint(&b, end);
                if (f == 5 && !msg && L < 4u * 1024 * 1024 && b + L <= end) { msg = malloc(L + 1); if (msg) { memcpy(msg, b, L); msg[L] = 0; } }
                b += L; }
            else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        const char *who = user_name(p, actor);
        char wbuf[32]; if (!who) { snprintf(wbuf, sizeof wbuf, "user %u", actor); who = wbuf; }

        const char *target = "direct";
        if (have_chan) { mch_t *c = chan_by_id(p, channel); if (c) target = c->name; }
        else target = who;
        char *text = msg ? mum_html_to_text(msg) : NULL;
        tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), target, text ? text : "", who, 0 };
        tri_emit(tri_account_core(a), &ev);
        free(text); free(msg);
        return;
    }
    if (type == MT_REJECT) {
        char reason[256] = "rejected";
        while (b < end) {
            uint64_t tag = rd_varint(&b, end); int f = tag >> 3, wt = tag & 7;
            if (wt == 2) { uint64_t L = rd_varint(&b, end); if (f == 2 && L < sizeof reason) { memcpy(reason, b, L); reason[L] = 0; } b += L; }
            else if (wt == 0) rd_varint(&b, end); else if (wt == 5) b += 4; else if (wt == 1) b += 8;
        }
        tri_set_error("mumble: server rejected login: %s", reason);
        emit(a, TRI_EV_ERROR, NULL, tri_last_error());
        mum_teardown(a, NULL);
        tri_account_set_state(a, TRI_CS_OFFLINE);
        return;
    }
    if (type == MT_UDPTUNNEL) {
        if (n < 1) return;
        int vtype = b[0] >> 5;
        if (vtype != 4) return;
        const uint8_t *q = b + 1, *e = b + n;
        uint32_t session = rd_mvar(&q, e);
        (void)rd_mvar(&q, e);
        uint64_t oh = rd_mvar(&q, e);
        int olen = oh & 0x1FFF;
        if (q + olen > e) olen = (int)(e - q);
        if (olen > 0) play_voice(a, session, q, olen);
        return;
    }

}

static void mum_on_readable(account_t *a, int fd) {
    mum_priv *p = tri_account_priv(a);
    if (!p) return;
    (void)fd;
    if (p->state == ST_TLS_HS) { tls_pump(a); return; }
    if (p->state != ST_ONLINE) return;

    for (;;) {
        int r = wolfSSL_read(p->ssl, p->rbuf + p->rlen, sizeof p->rbuf - p->rlen);
        if (r <= 0) {
            int e = wolfSSL_get_error(p->ssl, r);
            if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE) return;
            mum_teardown(a, NULL);
            tri_account_notify_down(a, r == 0 ? "connection closed by server" : "connection error");
            return;
        }
        p->rlen += r;
        size_t off = 0;
        while (p->rlen - off >= 6) {
            const uint8_t *h = p->rbuf + off;
            int type = (h[0] << 8) | h[1];
            uint32_t len = (h[2] << 24) | (h[3] << 16) | (h[4] << 8) | h[5];
            if (len > sizeof p->rbuf - 6) { mum_teardown(a, NULL); tri_account_notify_down(a, "mumble: oversized frame"); return; }
            if (p->rlen - off - 6 < len) break;
            handle_message(a, type, h + 6, len);
            if (tri_account_priv(a) == NULL) return;
            off += 6 + len;
        }
        if (off) { memmove(p->rbuf, p->rbuf + off, p->rlen - off); p->rlen -= off; }
    }
}

static void mum_on_writable(account_t *a, int fd) {
    mum_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->state == ST_CONNECTING) {
        int err = 0; socklen_t l = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) { tri_set_error("mumble: connect to %s:%s failed: %s", p->host, p->port, strerror(err));
                   char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                   mum_teardown(a, NULL); tri_account_notify_down(a, m); return; }
        p->state = ST_TLS_HS;
        tls_pump(a);
        return;
    }
    if (p->state == ST_TLS_HS) tls_pump(a);
}

static int mum_send_text(account_t *a, const char *target, const char *body) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("mumble: not connected yet");

    uint8_t b[1200]; size_t n;
    mch_t *c = (target && target[0] && strcmp(target, "text")) ? chan_by_name(p, target) : NULL;
    if (!c && target && target[0]) {
        muser_t *u = user_find_by_name(p, target);
        if (u) { n = pb_u32(b, 2, u->session); n += pb_str(b + n, 5, body); return mum_send(a, MT_TEXTMESSAGE, b, n); }
    }
    uint32_t chan = c ? c->id : p->self_channel;
    n = pb_u32(b, 3, chan);
    n += pb_str(b + n, 5, body);
    return mum_send(a, MT_TEXTMESSAGE, b, n);
}

static void mum_join(account_t *a, const char *target) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return;
    mch_t *c = chan_by_name(p, target);
    if (!c) { emit(a, TRI_EV_ERROR, NULL, tri_set_error("mumble: no channel named '%s'", target) ? tri_last_error() : ""); return; }
    uint8_t m[32]; size_t mn = pb_u32(m, 1, p->session); mn += pb_u32(m + mn, 5, c->id);
    mum_send(a, MT_USERSTATE, m, mn);
}

static int mum_moderate(account_t *a, const char *channel, const char *user, const char *action, const char *arg) {
    (void)channel;
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("mumble: not connected");

    if (!strcmp(action, "self-mute") || !strcmp(action, "self-deaf")) {
        if (!strcmp(action, "self-deaf")) { p->self_deaf = !p->self_deaf; if (p->self_deaf) p->self_mute = 1; }
        else                              { p->self_mute = !p->self_mute; if (!p->self_mute) p->self_deaf = 0; }
        uint8_t b[32]; size_t n = pb_u32(b, 1, p->session);
        n += pb_u32(b + n, 9, p->self_mute ? 1 : 0);
        n += pb_u32(b + n, 10, p->self_deaf ? 1 : 0);
        mum_send(a, MT_USERSTATE, b, n);
        emit(a, TRI_EV_STATUS, NULL, p->self_deaf ? "you are deafened" : p->self_mute ? "you are muted" : "mic live");
        return 0;
    }
    muser_t *u = user ? user_find_by_name(p, user) : NULL;
    if (!u) return tri_set_error("mumble: no user '%s' in view", user ? user : "");
    uint8_t b[300]; size_t n = pb_u32(b, 1, u->session);
    if (!strcmp(action, "kick") || !strcmp(action, "ban")) {
        if (arg && arg[0]) n += pb_str(b + n, 3, arg);
        n += pb_u32(b + n, 4, !strcmp(action, "ban") ? 1 : 0);
        return mum_send(a, MT_USERREMOVE, b, n);
    }
    if (!strcmp(action, "mute"))       n += pb_u32(b + n, 6, 1);
    else if (!strcmp(action, "unmute"))n += pb_u32(b + n, 6, 0);
    else if (!strcmp(action, "deaf"))  n += pb_u32(b + n, 7, 1);
    else if (!strcmp(action, "undeaf"))n += pb_u32(b + n, 7, 0);
    else if (!strcmp(action, "move")) {
        mch_t *c = arg ? chan_by_name(p, arg) : NULL;
        if (!c) return tri_set_error("mumble: no channel '%s' to move to", arg ? arg : "");
        n += pb_u32(b + n, 5, c->id);
    } else return tri_set_error("mumble: unsupported moderation action '%s'", action);
    return mum_send(a, MT_USERSTATE, b, n);
}

static int mum_user_info(account_t *a, const char *channel, const char *user) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("mumble: not connected");
    muser_t *u = user ? user_find_by_name(p, user) : NULL;
    if (!u) return tri_set_error("mumble: no user '%s'", user ? user : "");
    mch_t *c = chan_by_id(p, u->channel_id);
    char m[256]; snprintf(m, sizeof m, "%s - session %u, channel %s%s", u->name, u->session,
                          c ? c->name : "(unknown)", u->talking ? ", speaking" : "");
    tri_event_t ev = { TRI_EV_STATUS, tri_account_key(a), channel, m, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
    return 0;
}

static int mum_upload(account_t *a, const char *target, const char *path) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("mumble: not connected yet");
    const char *ctype = img_ctype(path);
    if (!ctype) return tri_set_error("mumble: only image files (png/jpg/gif/webp/bmp) can be embedded inline");
    FILE *f = fopen(path, "rb");
    if (!f) return tri_set_error("mumble: cannot open '%s': %s", path, strerror(errno));
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return tri_set_error("mumble: '%s' is empty or unreadable", path); }
    if (sz > 90L * 1024) { fclose(f); return tri_set_error("mumble: image is %ld KB - inline images must be ~90 KB or less (server ImageMessageLength)", sz / 1024); }
    unsigned char *raw = malloc((size_t)sz);
    if (!raw) { fclose(f); return tri_set_error("mumble: out of memory"); }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { free(raw); fclose(f); return tri_set_error("mumble: read error on '%s'", path); }
    fclose(f);
    char *b64 = malloc(4 * (((size_t)sz + 2) / 3) + 1);
    if (!b64) { free(raw); return tri_set_error("mumble: out of memory"); }
    tri_b64enc(raw, (size_t)sz, b64); free(raw);
    size_t bodycap = strlen(b64) + 64;
    char *body = malloc(bodycap);
    if (!body) { free(b64); return tri_set_error("mumble: out of memory"); }
    snprintf(body, bodycap, "<img src=\"data:%s;base64,%s\"/>", ctype, b64); free(b64);
    uint32_t chan = p->self_channel;
    if (target && target[0] && strcmp(target, "text")) { mch_t *c = chan_by_name(p, target); if (c) chan = c->id; }
    uint8_t *pay = malloc(strlen(body) + 32);
    if (!pay) { free(body); return tri_set_error("mumble: out of memory"); }
    size_t n = pb_u32(pay, 3, chan);
    n += pb_str(pay + n, 5, body);
    int rc = mum_send(a, MT_TEXTMESSAGE, pay, n);
    free(pay); free(body);
    if (rc == 0) emit(a, TRI_EV_STATUS, target, "sent image");
    return rc;
}

static int rd_u32le(const uint8_t *b) { return b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24; }

static int load_wav(const char *path, int16_t **out, size_t *out_n) {
    FILE *f = fopen(path, "rb");
    if (!f) return tri_set_error("mumble: cannot open '%s': %s", path, strerror(errno));
    uint8_t hdr[12];
    if (fread(hdr, 1, 12, f) != 12 || memcmp(hdr, "RIFF", 4) || memcmp(hdr + 8, "WAVE", 4))
        { fclose(f); return tri_set_error("mumble: '%s' is not a WAV file", path); }
    int chans = 0, rate = 0, bits = 0;
    uint8_t ch[8];
    while (fread(ch, 1, 8, f) == 8) {
        uint32_t sz = rd_u32le(ch + 4);
        if (!memcmp(ch, "fmt ", 4)) {
            uint8_t fmt[16]; if (fread(fmt, 1, 16, f) != 16) break;
            chans = fmt[2] | fmt[3] << 8; rate = rd_u32le(fmt + 4); bits = fmt[14] | fmt[15] << 8;
            if (sz > 16) fseek(f, sz - 16, SEEK_CUR);
        } else if (!memcmp(ch, "data", 4)) {
            if (chans != 1 || rate != SAMPLE_RATE || bits != 16) {
                fclose(f);
                return tri_set_error("mumble: '%s' must be 48000Hz mono 16-bit (got %dHz, %dch, %d-bit) - convert with: ffmpeg -i in -ar 48000 -ac 1 -c:a pcm_s16le out.wav", path, rate, chans, bits);
            }
            int16_t *pcm = malloc(sz);
            if (!pcm) { fclose(f); return tri_set_error("mumble: out of memory for '%s'", path); }
            size_t got = fread(pcm, 1, sz, f);
            fclose(f);
            *out = pcm; *out_n = got / 2;
            return 0;
        } else fseek(f, sz, SEEK_CUR);
    }
    fclose(f);
    return tri_set_error("mumble: '%s' has no data chunk", path);
}

static int mum_play(account_t *a, const char *path) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("mumble: not connected - can't play");
    int16_t *pcm = NULL; size_t pcm_n = 0;
    if (load_wav(path, &pcm, &pcm_n) != 0) return -1;
    if (!p->enc) {
        int err; p->enc = opus_encoder_create(SAMPLE_RATE, 1, OPUS_APPLICATION_AUDIO, &err);
        if (!p->enc) { free(pcm); return tri_set_error("mumble: opus encoder init failed (%d)", err); }
        opus_encoder_ctl(p->enc, OPUS_SET_BITRATE(48000));
    }
    free(p->pcm);
    p->pcm = pcm; p->pcm_n = pcm_n; p->pcm_pos = 0; p->aseq = 0;
    p->playing = 1; p->play_start = now_s();
    char m[128]; snprintf(m, sizeof m, "soundboard: playing %s (%.1fs)", path, (double)pcm_n / SAMPLE_RATE);
    emit(a, TRI_EV_STATUS, NULL, m);
    return 0;
}

static void send_voice_frame(account_t *a, const uint8_t *opus, int olen, int last) {
    uint8_t vp[1500]; size_t vl = 0;
    mum_priv *p = tri_account_priv(a);
    vp[vl++] = 0x80;
    vl += mvar(vp + vl, p->aseq);
    vl += mvar(vp + vl, (uint32_t)olen | (last ? 0x2000 : 0));
    memcpy(vp + vl, opus, olen); vl += olen;
    mum_send(a, MT_UDPTUNNEL, vp, vl);
}

static void mum_mic_stop(account_t *a) {
    mum_priv *p = tri_account_priv(a);
    if (!p->mic) return;
    tri_core_remove_fd(tri_account_core(a), tri_audio_source_fd(p->mic));
    tri_audio_capture_close(p->mic); p->mic = NULL; p->mic_n = 0;
}
static void mum_mic_readable(void *ud, int fd) {
    (void)fd; account_t *a = ud; mum_priv *p = tri_account_priv(a);
    if (!p || !p->mic) return;
    for (;;) {
        int got = tri_audio_source_read(p->mic, p->mic_acc + p->mic_n, FRAME_SAMPLES - p->mic_n);
        if (got < 0) { mum_mic_stop(a); emit(a, TRI_EV_STATUS, NULL, "mic: recorder stopped"); return; }
        if (got == 0) break;
        p->mic_n += got;
        if (p->mic_n >= FRAME_SAMPLES) {
            if (!p->playing && p->enc && !p->self_mute) {
                uint8_t opus[1000];
                int n = opus_encode(p->enc, p->mic_acc, FRAME_SAMPLES, opus, sizeof opus);
                if (n > 0) { send_voice_frame(a, opus, n, 0); p->aseq += 2; }
            }
            p->mic_n = 0;
        }
    }
}
static int mum_mic(account_t *a, int on) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("mumble: not connected");
    if (!on) { mum_mic_stop(a); emit(a, TRI_EV_STATUS, NULL, "mic off"); return 0; }
    if (p->mic) return 0;
    if (!p->enc) {
        int err; p->enc = opus_encoder_create(SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &err);
        if (!p->enc) return tri_set_error("mumble: opus encoder init failed (%d)", err);
        opus_encoder_ctl(p->enc, OPUS_SET_BITRATE(48000));
    }
    p->mic = tri_audio_capture_open(tri_account_core(a), "");
    if (!p->mic) return -1;
    p->mic_n = 0;
    tri_core_add_fd(tri_account_core(a), tri_audio_source_fd(p->mic), mum_mic_readable, a);
    emit(a, TRI_EV_STATUS, NULL, "mic on - transmitting to the channel");
    return 0;
}

static void mum_tick(account_t *a) {
    mum_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return;
    double t = now_s();
    if (t - p->last_ping >= 5.0) { send_ping(a); p->last_ping = t; }

    for (int i = 0; i < p->nusers; i++)
        if (p->users[i].talking && t - p->users[i].last_voice > 0.4) { p->users[i].talking = 0; roster_push(a, &p->users[i]); }

    if (!p->playing) return;

    size_t due = (size_t)((t - p->play_start) / 0.01);
    while (p->playing && p->aseq < due && p->pcm_pos < p->pcm_n) {
        int16_t frame[FRAME_SAMPLES];
        size_t avail = p->pcm_n - p->pcm_pos;
        size_t cnt = avail < FRAME_SAMPLES ? avail : FRAME_SAMPLES;
        memcpy(frame, p->pcm + p->pcm_pos, cnt * 2);
        if (cnt < FRAME_SAMPLES) memset(frame + cnt, 0, (FRAME_SAMPLES - cnt) * 2);
        p->pcm_pos += cnt;
        int last = p->pcm_pos >= p->pcm_n;
        uint8_t opus[4000];
        int olen = opus_encode(p->enc, frame, FRAME_SAMPLES, opus, sizeof opus);
        if (olen > 0) send_voice_frame(a, opus, olen, last);
        p->aseq += 2;
        if (last) { p->playing = 0; free(p->pcm); p->pcm = NULL; emit(a, TRI_EV_STATUS, NULL, "soundboard: done"); }
    }
}

const protocol_backend_t backend_mumble = {
    .name = "mumble",
    .connect = mum_connect,
    .disconnect = mum_disconnect,
    .send_message = mum_send_text,
    .join = mum_join,
    .leave = NULL,
    .on_socket_readable = mum_on_readable,
    .on_socket_writable = mum_on_writable,
    .tick = mum_tick,
    .play_file = mum_play,
    .mic = mum_mic,
    .upload = mum_upload,
    .moderate = mum_moderate,
    .user_info = mum_user_info,
    .record = mum_record,
};
