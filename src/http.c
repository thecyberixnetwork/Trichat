#include "trichat.h"
#include "http.h"
#include "resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>

#ifdef TRI_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif

#define HTTP_MAX_RESP (32u * 1024u * 1024u)

enum { HX_RESOLVE, HX_CONNECT, HX_TLS, HX_SEND, HX_RECV };

typedef struct http_xfer {
    struct http_xfer *next;
    tri_core *core;
    int fd, state, tls, want_write;
    int follow, redirs;
    tri_resolve *resolve;
    char host[256], port[8];
    char *req; size_t reqlen, reqoff;
    char *resp; size_t resplen, respcap;
    tri_http_cb cb; void *ud;
#ifdef TRI_TLS
    WOLFSSL_CTX *ctx; WOLFSSL *ssl;
#endif
} http_xfer;

static http_xfer *g_list;

static ssize_t io_write(http_xfer *x, const char *b, size_t n) {
#ifdef TRI_TLS
    if (x->tls) return wolfSSL_write(x->ssl, b, (int)n);
#endif
    return write(x->fd, b, n);
}
static ssize_t io_read(http_xfer *x, char *b, size_t n) {
#ifdef TRI_TLS
    if (x->tls) return wolfSSL_read(x->ssl, b, (int)n);
#endif
    return read(x->fd, b, n);
}
static int io_wouldblock(http_xfer *x, ssize_t r) {
#ifdef TRI_TLS
    if (x->tls) { int e = wolfSSL_get_error(x->ssl, (int)r);
                  return e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE; }
#endif
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

static int parse_url(const char *url, int *tls, char *host, size_t hsz, char *port, size_t psz, char *path, size_t pathsz) {
    if (!strncmp(url, "https://", 8)) { *tls = 1; url += 8; }
    else if (!strncmp(url, "http://", 7)) { *tls = 0; url += 7; }
    else return tri_set_error("http: url must be http:// or https:// (got '%s')", url);
    const char *slash = strchr(url, '/');
    char hp[300]; size_t hl = slash ? (size_t)(slash - url) : strlen(url);
    if (hl >= sizeof hp) hl = sizeof hp - 1;
    memcpy(hp, url, hl); hp[hl] = '\0';
    snprintf(path, pathsz, "%s", slash ? slash : "/");
    char *colon = strchr(hp, ':');
    if (colon) { *colon = '\0'; snprintf(port, psz, "%s", colon + 1); }
    else        snprintf(port, psz, "%s", *tls ? "443" : "80");
    snprintf(host, hsz, "%s", hp);
    if (!host[0]) return tri_set_error("http: no host in url '%s'", url);
    return 0;
}

static void xfer_teardown(http_xfer *x) {
    if (x->resolve) tri_resolve_cancel(x->resolve);
#ifdef TRI_TLS
    if (x->ssl) wolfSSL_free(x->ssl);
    if (x->ctx) wolfSSL_CTX_free(x->ctx);
#endif
    if (x->fd >= 0) close(x->fd);
    free(x->req); free(x->resp);
    for (http_xfer **pp = &g_list; *pp; pp = &(*pp)->next)
        if (*pp == x) { *pp = x->next; break; }
    free(x);
}

static void get_header(const char *hstart, const char *hend, const char *name, char *out, size_t osz) {
    out[0] = '\0'; size_t nl = strlen(name);
    for (const char *p = hstart; p && p < hend; ) {
        const char *eol = strstr(p, "\r\n"); if (!eol || eol > hend) break;
        if ((size_t)(eol - p) > nl && p[nl] == ':' && !strncasecmp(p, name, nl)) {
            const char *v = p + nl + 1; while (*v == ' ') v++;
            size_t vl = (size_t)(eol - v); if (vl >= osz) vl = osz - 1;
            memcpy(out, v, vl); out[vl] = '\0'; return;
        }
        p = eol + 2;
    }
}

static int ci_contains(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) if (!strncasecmp(p, needle, nl)) return 1;
    return 0;
}

static size_t dechunk(char *buf, size_t len) {
    char *src = buf, *dst = buf, *end = buf + len;
    for (;;) {
        char *nl = src;
        while (nl + 1 < end && !(nl[0] == '\r' && nl[1] == '\n')) nl++;
        if (nl + 1 >= end) break;
        unsigned long csz = strtoul(src, NULL, 16);
        src = nl + 2;
        if (csz == 0) break;
        if (src + csz > end) csz = (unsigned long)(end - src);
        memmove(dst, src, csz); dst += csz; src += csz;
        if (src + 2 <= end && src[0] == '\r' && src[1] == '\n') src += 2;
    }
    return (size_t)(dst - buf);
}

static int resolve_location(http_xfer *x, const char *loc, char *out, size_t osz) {
    if (!strncmp(loc, "http://", 7) || !strncmp(loc, "https://", 8)) { snprintf(out, osz, "%s", loc); return 0; }
    const char *scheme = x->tls ? "https" : "http";
    int defport = (x->tls && !strcmp(x->port, "443")) || (!x->tls && !strcmp(x->port, "80"));
    if (loc[0] == '/' && loc[1] == '/') { snprintf(out, osz, "%s:%s", scheme, loc); return 0; }
    const char *path = loc[0] == '/' ? loc : NULL;
    char pbuf[1088]; if (!path) { snprintf(pbuf, sizeof pbuf, "/%s", loc); path = pbuf; }
    if (defport) snprintf(out, osz, "%s://%s%s", scheme, x->host, path);
    else         snprintf(out, osz, "%s://%s:%s%s", scheme, x->host, x->port, path);
    return 0;
}

static int http_get_follow(tri_core *c, const char *url, tri_http_cb cb, void *ud, int redirs);

static void xfer_finish(http_xfer *x, int ok) {
    int status = 0; const char *body = ""; size_t blen = 0; char ctype[160] = "";
    if (ok && x->resp) {
        x->resp[x->resplen] = '\0';
        if (!strncmp(x->resp, "HTTP/", 5)) { const char *sp = strchr(x->resp, ' '); if (sp) status = atoi(sp + 1); }
        char *hend = strstr(x->resp, "\r\n\r\n");
        if (hend) {
            get_header(x->resp, hend, "content-type", ctype, sizeof ctype);
            char *bodyp = hend + 4; blen = x->resplen - (size_t)(bodyp - x->resp);

            if (x->follow && (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) && x->redirs < 8) {
                char loc[1024] = ""; get_header(x->resp, hend, "location", loc, sizeof loc);
                char nu[1600];
                if (loc[0] && resolve_location(x, loc, nu, sizeof nu) == 0 &&
                    http_get_follow(x->core, nu, x->cb, x->ud, x->redirs + 1) == 0) {
                    xfer_teardown(x); return;
                }

            }
            char te[64] = ""; get_header(x->resp, hend, "transfer-encoding", te, sizeof te);
            if (ci_contains(te, "chunked")) blen = dechunk(bodyp, blen);
            body = bodyp;
        }
    }
    x->cb(x->ud, ok, status, body, blen, ctype);
    xfer_teardown(x);
}

#ifdef TRI_TLS
static void tls_pump(http_xfer *x) {
    if (wolfSSL_connect(x->ssl) == WOLFSSL_SUCCESS) { x->state = HX_SEND; x->want_write = 1; return; }
    int err = wolfSSL_get_error(x->ssl, 0);
    if (err == WOLFSSL_ERROR_WANT_WRITE) { x->want_write = 1; return; }
    if (err == WOLFSSL_ERROR_WANT_READ)  { x->want_write = 0; return; }
    char e[80]; wolfSSL_ERR_error_string(err, e);
    tri_set_error("http: TLS handshake with %s failed: %s", x->host, e);
    xfer_finish(x, 0);
}
#endif

static void pump(http_xfer *x, int readable, int writable) {
    if (x->state == HX_CONNECT) {
        if (!writable) return;
        int err = 0; socklen_t l = sizeof err;
        getsockopt(x->fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) { tri_set_error("http: connect to %s:%s failed: %s", x->host, x->port, strerror(err)); xfer_finish(x, 0); return; }
#ifdef TRI_TLS
        if (x->tls) { x->state = HX_TLS; tls_pump(x); return; }
#endif
        x->state = HX_SEND; x->want_write = 1;
    }
#ifdef TRI_TLS
    if (x->state == HX_TLS) { tls_pump(x); return; }
#endif
    if (x->state == HX_SEND) {
        while (x->reqoff < x->reqlen) {
            ssize_t w = io_write(x, x->req + x->reqoff, x->reqlen - x->reqoff);
            if (w > 0) { x->reqoff += (size_t)w; continue; }
            if (io_wouldblock(x, w)) { x->want_write = 1; return; }
            tri_set_error("http: send to %s failed", x->host); xfer_finish(x, 0); return;
        }
        x->want_write = 0; x->state = HX_RECV;
    }
    if (x->state == HX_RECV) {
        if (!readable) return;
        for (;;) {
            if (x->resplen + 4096 + 1 > x->respcap) {
                size_t nc = x->respcap ? x->respcap * 2 : 8192;
                while (nc < x->resplen + 4096 + 1) nc *= 2;
                if (nc > HTTP_MAX_RESP) { tri_set_error("http: response from %s exceeds %u MB", x->host, HTTP_MAX_RESP / (1024 * 1024)); xfer_finish(x, 0); return; }
                char *nb = realloc(x->resp, nc); if (!nb) { tri_set_error("http: out of memory"); xfer_finish(x, 0); return; }
                x->resp = nb; x->respcap = nc;
            }
            ssize_t r = io_read(x, x->resp + x->resplen, x->respcap - x->resplen - 1);
            if (r > 0) { x->resplen += (size_t)r; continue; }
            if (r == 0) { xfer_finish(x, 1); return; }
            if (io_wouldblock(x, r)) return;

            xfer_finish(x, x->resplen > 0 ? 1 : 0);
            return;
        }
    }
}

static void http_resolved(void *ud, int ok, const struct sockaddr *sa, socklen_t salen,
                          int socktype, int proto, const char *err) {
    http_xfer *x = ud;
    x->resolve = NULL;
    if (!ok) { tri_set_error("http: cannot resolve %s:%s: %s", x->host, x->port, err); xfer_finish(x, 0); return; }
    int fd = socket(sa->sa_family, socktype, proto);
    if (fd < 0) { tri_set_error("http: socket() failed: %s", strerror(errno)); xfer_finish(x, 0); return; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int rc = connect(fd, sa, salen);
    if (rc != 0 && errno != EINPROGRESS) {
        tri_set_error("http: connect to %s:%s failed: %s", x->host, x->port, strerror(errno));
        close(fd); xfer_finish(x, 0); return;
    }
    x->fd = fd; x->state = HX_CONNECT; x->want_write = 1;
#ifdef TRI_TLS
    if (x->tls) {
        static int inited = 0; if (!inited) { wolfSSL_Init(); inited = 1; }
        x->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        if (!x->ctx) { tri_set_error("http: wolfSSL_CTX_new failed"); xfer_finish(x, 0); return; }
        wolfSSL_CTX_load_system_CA_certs(x->ctx);
        wolfSSL_CTX_set_verify(x->ctx, WOLFSSL_VERIFY_PEER, NULL);
        x->ssl = wolfSSL_new(x->ctx);
        wolfSSL_set_fd(x->ssl, fd);

        if (!(x->host[0] >= '0' && x->host[0] <= '9') && !strchr(x->host, ':'))
            wolfSSL_UseSNI(x->ssl, WOLFSSL_SNI_HOST_NAME, x->host, (unsigned short)strlen(x->host));
        wolfSSL_check_domain_name(x->ssl, x->host);
    }
#endif
}

static http_xfer *xfer_new(tri_core *c, const char *url, char **out_path) {
    int tls = 0; char host[256], port[8], path[2048];
    if (parse_url(url, &tls, host, sizeof host, port, sizeof port, path, sizeof path) != 0) return NULL;
#ifndef TRI_TLS
    if (tls) { tri_set_error("http: https:// needs a TLS build (rebuild with wolfSSL)"); return NULL; }
#endif
    http_xfer *x = calloc(1, sizeof *x);
    if (!x) { tri_set_error("http: out of memory"); return NULL; }
    x->core = c; x->fd = -1; x->tls = tls; x->state = HX_RESOLVE; x->want_write = 0;
    snprintf(x->host, sizeof x->host, "%s", host);
    snprintf(x->port, sizeof x->port, "%s", port);
    if (out_path) { *out_path = strdup(path); if (!*out_path) { free(x); tri_set_error("http: out of memory"); return NULL; } }
    x->resolve = tri_resolve_start(c, x->host, x->port, SOCK_STREAM, http_resolved, x);
    if (!x->resolve) { if (out_path) free(*out_path); free(x); return NULL; }
    x->next = g_list; g_list = x;
    return x;
}

static int http_get_follow(tri_core *c, const char *url, tri_http_cb cb, void *ud, int redirs) {
    char *path = NULL;
    http_xfer *x = xfer_new(c, url, &path);
    if (!x) return -1;
    x->follow = 1; x->redirs = redirs;
    char hdr[3072];
    int n = snprintf(hdr, sizeof hdr,
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Trichat\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, x->host);
    free(path);
    if (n < 0 || n >= (int)sizeof hdr) { xfer_teardown(x); return tri_set_error("http: request line too long"); }
    x->req = malloc((size_t)n); if (!x->req) { xfer_teardown(x); return tri_set_error("http: out of memory"); }
    memcpy(x->req, hdr, (size_t)n); x->reqlen = (size_t)n;
    x->cb = cb; x->ud = ud;
    return 0;
}

int tri_http_get(tri_core *c, const char *url, tri_http_cb cb, void *ud) {
    return http_get_follow(c, url, cb, ud, 0);
}

int tri_http_put(tri_core *c, const char *url, const char *content_type, const void *data, size_t len,
                 const char *const *extra_headers, int n_extra, tri_http_cb cb, void *ud) {
    char *path = NULL;
    http_xfer *x = xfer_new(c, url, &path);
    if (!x) return -1;
    char hdr[4096];
    int n = snprintf(hdr, sizeof hdr,
        "PUT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Trichat\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n",
        path, x->host, content_type ? content_type : "application/octet-stream", len);
    free(path);
    for (int i = 0; i < n_extra && n < (int)sizeof hdr; i++)
        n += snprintf(hdr + n, sizeof hdr - n, "%s\r\n", extra_headers[i]);
    if (n < (int)sizeof hdr) n += snprintf(hdr + n, sizeof hdr - n, "\r\n");
    if (n < 0 || n >= (int)sizeof hdr) { xfer_teardown(x); return tri_set_error("http: request headers too long"); }
    x->req = malloc((size_t)n + len);
    if (!x->req) { xfer_teardown(x); return tri_set_error("http: out of memory"); }
    memcpy(x->req, hdr, (size_t)n);
    if (len) memcpy(x->req + n, data, len);
    x->reqlen = (size_t)n + len;
    x->cb = cb; x->ud = ud;
    return 0;
}

int tri_http_fdset(tri_core *c, fd_set *r, fd_set *w) {
    int mx = -1;
    for (http_xfer *x = g_list; x; x = x->next) {
        if (x->core != c || x->fd < 0) continue;
        FD_SET(x->fd, r);
        if (x->want_write) FD_SET(x->fd, w);
        if (x->fd > mx) mx = x->fd;
    }
    return mx;
}

void tri_http_service(tri_core *c, fd_set *r, fd_set *w) {
    for (http_xfer *x = g_list; x; ) {
        http_xfer *next = x->next;
        if (x->core == c && x->fd >= 0) {
            int rd = FD_ISSET(x->fd, r), wr = FD_ISSET(x->fd, w);
            if (rd || wr) pump(x, rd, wr);
        }
        x = next;
    }
}

void tri_http_shutdown(tri_core *c) {
    for (http_xfer *x = g_list; x; ) {
        http_xfer *next = x->next;
        if (x->core == c) xfer_teardown(x);
        x = next;
    }
}
