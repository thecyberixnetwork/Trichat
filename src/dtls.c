#include "dtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#define DTLS_INQ   8
#define DTLS_DGRAM 1600
#define SRTP_PROFILE "SRTP_AES128_CM_SHA1_80"

struct dtls_srtp {
    int client;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    dtls_send_fn send; void *send_ud;
    struct { uint8_t data[DTLS_DGRAM]; int len; } inq[DTLS_INQ];
    int inq_head, inq_tail, inq_n;
    char fp[128];
    char peer_fp[128];
    int  started, done, failed;
    char err[160];
    char profile[48];
    double retransmit_at;
    uint8_t keys[128]; int keylen;
};

static double dtls_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) == 0) return t.tv_sec + t.tv_nsec / 1e9;
    return (double)time(NULL);
}

static void dtls_arm_timer(dtls_srtp *d) {
    int to = wolfSSL_dtls_get_current_timeout(d->ssl);
    if (to <= 0) to = 1;
    d->retransmit_at = dtls_now() + (double)to;
}

static int dtls_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl; dtls_srtp *d = (dtls_srtp *)ctx;
    if (d->inq_n == 0) return WOLFSSL_CBIO_ERR_WANT_READ;
    int i = d->inq_head, n = d->inq[i].len;
    if (n > sz) n = sz;
    memcpy(buf, d->inq[i].data, (size_t)n);
    d->inq_head = (d->inq_head + 1) % DTLS_INQ; d->inq_n--;
    return n;
}
static int dtls_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl; dtls_srtp *d = (dtls_srtp *)ctx;
    if (d->send) d->send(d->send_ud, (const uint8_t *)buf, sz);
    return sz;
}
static int verify_allow(int preverify, WOLFSSL_X509_STORE_CTX *st) {
    (void)preverify; (void)st; return 1;
}
static void enqueue(dtls_srtp *d, const uint8_t *data, int len) {
    if (len <= 0 || len > DTLS_DGRAM || d->inq_n >= DTLS_INQ) return;
    int i = d->inq_tail;
    memcpy(d->inq[i].data, data, (size_t)len); d->inq[i].len = len;
    d->inq_tail = (d->inq_tail + 1) % DTLS_INQ; d->inq_n++;
}

static void fp_of(const uint8_t *der, int len, char *out, size_t osz) {
    uint8_t h[32]; wc_Sha256 s;
    wc_InitSha256(&s); wc_Sha256Update(&s, der, (word32)len); wc_Sha256Final(&s, h); wc_Sha256Free(&s);
    int o = 0;
    for (int i = 0; i < 32 && o + 3 < (int)osz; i++) o += snprintf(out + o, osz - (size_t)o, "%s%02X", i ? ":" : "", h[i]);
}

static int make_self_cert(uint8_t *cert, int *certlen, uint8_t *key, int *keylen) {
    WC_RNG rng; if (wc_InitRng(&rng) != 0) return -1;
    ecc_key ek; int rc = -1;
    if (wc_ecc_init(&ek) != 0) { wc_FreeRng(&rng); return -1; }
    if (wc_ecc_make_key(&rng, 32, &ek) != 0) goto done;
    {
        Cert c; if (wc_InitCert(&c) != 0) goto done;
        strncpy(c.subject.commonName, "trichat", CTC_NAME_SIZE - 1);
        c.sigType = CTC_SHA256wECDSA; c.daysValid = 3650; c.selfSigned = 1;
        int body = wc_MakeCert(&c, cert, 4096, NULL, &ek, &rng);
        if (body <= 0) goto done;
        int total = wc_SignCert(c.bodySz, c.sigType, cert, 4096, NULL, &ek, &rng);
        if (total <= 0) goto done;
        *certlen = total;
        int kl = wc_EccKeyToDer(&ek, key, 512);
        if (kl <= 0) goto done;
        *keylen = kl;
        rc = 0;
    }
done:
    wc_ecc_free(&ek); wc_FreeRng(&rng);
    return rc;
}

dtls_srtp *dtls_srtp_new(int client, dtls_send_fn send, void *send_ud) {
    static int inited = 0; if (!inited) { wolfSSL_Init(); inited = 1; }
    dtls_srtp *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->client = client; d->send = send; d->send_ud = send_ud;
    uint8_t cert[4096], key[512]; int certlen = 0, keylen = 0;
    if (make_self_cert(cert, &certlen, key, &keylen) != 0) { free(d); return NULL; }
    fp_of(cert, certlen, d->fp, sizeof d->fp);
    d->ctx = wolfSSL_CTX_new(client ? wolfDTLSv1_2_client_method() : wolfDTLSv1_2_server_method());
    if (!d->ctx) { free(d); return NULL; }
    if (wolfSSL_CTX_use_certificate_buffer(d->ctx, cert, certlen, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(d->ctx, key, keylen, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(d->ctx); free(d); return NULL;
    }

    wolfSSL_CTX_set_verify(d->ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_allow);
    if (wolfSSL_CTX_set_tlsext_use_srtp(d->ctx, SRTP_PROFILE) != 0) { wolfSSL_CTX_free(d->ctx); free(d); return NULL; }
    wolfSSL_CTX_SetIORecv(d->ctx, dtls_io_recv);
    wolfSSL_CTX_SetIOSend(d->ctx, dtls_io_send);
    d->ssl = wolfSSL_new(d->ctx);
    if (!d->ssl) { wolfSSL_CTX_free(d->ctx); free(d); return NULL; }
    wolfSSL_SetIOReadCtx(d->ssl, d);
    wolfSSL_SetIOWriteCtx(d->ssl, d);
    wolfSSL_dtls_set_using_nonblock(d->ssl, 1);
    wolfSSL_KeepArrays(d->ssl);

    return d;
}
void dtls_srtp_free(dtls_srtp *d) {
    if (!d) return;
    if (d->ssl) wolfSSL_free(d->ssl);
    if (d->ctx) wolfSSL_CTX_free(d->ctx);
    free(d);
}
void dtls_srtp_set_send(dtls_srtp *d, dtls_send_fn send, void *send_ud) { if (d) { d->send = send; d->send_ud = send_ud; } }
const char *dtls_srtp_fingerprint(dtls_srtp *d) { return d ? d->fp : ""; }
void dtls_srtp_set_peer_fingerprint(dtls_srtp *d, const char *fp) { if (d) snprintf(d->peer_fp, sizeof d->peer_fp, "%s", fp ? fp : ""); }
int  dtls_srtp_done(const dtls_srtp *d) { return d && d->done; }
int  dtls_srtp_keys(const dtls_srtp *d, uint8_t *out, int cap) {
    if (!d || !d->done || cap < d->keylen) return -1;
    memcpy(out, d->keys, (size_t)d->keylen);
    return d->keylen;
}

static int verify_peer_fp(dtls_srtp *d) {
    if (!d->peer_fp[0]) return 0;
    WOLFSSL_X509 *x = wolfSSL_get_peer_certificate(d->ssl);
    if (!x) return -1;
    int dl = 0; const unsigned char *pd = wolfSSL_X509_get_der(x, &dl);
    int ok = 0;
    if (pd && dl > 0) { char pf[128]; fp_of(pd, dl, pf, sizeof pf); ok = !strcasecmp(pf, d->peer_fp); }
    wolfSSL_X509_free(x);
    return ok ? 0 : -1;
}

static int pump(dtls_srtp *d) {
    if (!d || d->done) return d && d->done ? 1 : -1;
    if (d->failed) return -1;
    int ret = d->client ? wolfSSL_connect(d->ssl) : wolfSSL_accept(d->ssl);
    if (ret == WOLFSSL_SUCCESS) {
        if (verify_peer_fp(d) != 0) { d->failed = 1; snprintf(d->err, sizeof d->err, "peer certificate fingerprint mismatch"); return -1; }
        size_t klen = 0;
        wolfSSL_export_dtls_srtp_keying_material(d->ssl, NULL, &klen);
        if (klen == 0 || klen > sizeof d->keys) { d->failed = 1; snprintf(d->err, sizeof d->err, "SRTP key material size %zu unsupported", klen); return -1; }
        int r = wolfSSL_export_dtls_srtp_keying_material(d->ssl, d->keys, &klen);
        if (r != WOLFSSL_SUCCESS) { d->failed = 1; snprintf(d->err, sizeof d->err, "SRTP key export failed (%d) - KeepArrays?", r); return -1; }
        d->keylen = (int)klen; d->done = 1;
        const WOLFSSL_SRTP_PROTECTION_PROFILE *pr = wolfSSL_get_selected_srtp_profile(d->ssl);
        if (pr && pr->name) snprintf(d->profile, sizeof d->profile, "%s", pr->name);
        return 1;
    }
    int err = wolfSSL_get_error(d->ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) return 0;
    char eb[80] = ""; wolfSSL_ERR_error_string((unsigned long)err, eb);
    snprintf(d->err, sizeof d->err, "%s (err %d)", eb[0] ? eb : "handshake failed", err);
    d->failed = 1;
    return -1;
}
int dtls_srtp_failed(const dtls_srtp *d) { return d ? d->failed : 1; }
const char *dtls_srtp_error(const dtls_srtp *d) { return d && d->err[0] ? d->err : ""; }
const char *dtls_srtp_profile(const dtls_srtp *d) { return d && d->profile[0] ? d->profile : "?"; }

int dtls_srtp_start(dtls_srtp *d) { if (!d) return -1; d->started = 1; int r = pump(d); dtls_arm_timer(d); return r; }
int dtls_srtp_feed(dtls_srtp *d, const uint8_t *data, int len) {
    if (!d) return -1;
    enqueue(d, data, len);
    int r = pump(d);
    dtls_arm_timer(d);
    return r;
}
int dtls_srtp_tick(dtls_srtp *d) {
    if (!d || d->done || d->failed || !d->started) return d && d->done ? 1 : 0;
    if (dtls_now() < d->retransmit_at) return 0;
    if (wolfSSL_dtls_got_timeout(d->ssl) == WOLFSSL_SUCCESS) { dtls_arm_timer(d); return 0; }
    return pump(d);
}

static dtls_srtp *st_A, *st_B;
static void st_send(void *ud, const uint8_t *data, int len) {
    dtls_srtp *from = (dtls_srtp *)ud;
    enqueue(from == st_A ? st_B : st_A, data, len);
}
int dtls_srtp_selftest(void) {
    st_A = dtls_srtp_new(1, NULL, NULL);
    st_B = dtls_srtp_new(0, NULL, NULL);
    if (!st_A || !st_B) { dtls_srtp_free(st_A); dtls_srtp_free(st_B); st_A = st_B = NULL; return -1; }
    dtls_srtp_set_send(st_A, st_send, st_A);
    dtls_srtp_set_send(st_B, st_send, st_B);
    dtls_srtp_set_peer_fingerprint(st_A, dtls_srtp_fingerprint(st_B));
    dtls_srtp_set_peer_fingerprint(st_B, dtls_srtp_fingerprint(st_A));

    int rc = -2;
    dtls_srtp_start(st_A);
    for (int i = 0; i < 400 && !(dtls_srtp_done(st_A) && dtls_srtp_done(st_B)); i++) {
        pump(st_B); pump(st_A);
        if (st_A->failed || st_B->failed) break;
    }
    if (dtls_srtp_done(st_A) && dtls_srtp_done(st_B)) {
        uint8_t ka[128], kb[128];
        int la = dtls_srtp_keys(st_A, ka, sizeof ka), lb = dtls_srtp_keys(st_B, kb, sizeof kb);
        int nonzero = 0; for (int i = 0; i < la; i++) nonzero |= ka[i];

        if (la >= 60 && la == lb && nonzero && memcmp(ka, kb, (size_t)la) == 0) rc = 0;
        else rc = -3;
    }
    dtls_srtp_free(st_A); dtls_srtp_free(st_B); st_A = st_B = NULL;
    return rc;
}
