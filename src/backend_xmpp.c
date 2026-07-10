#include "trichat.h"
#include "util.h"
#include "resolve.h"
#include "omemo.h"
#include "jingle.h"
#include "ice.h"
#include "dtls.h"
#include "srtp.h"
#include "rtpvp8.h"
#include "ivf.h"
#include "rtph264.h"
#include "vdecode.h"
#ifdef TRI_X11
#include "x11cap.h"
#endif
#include <opus.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>

enum { ST_RESOLVING, ST_CONNECTING, ST_STREAM0, ST_TLS_HS, ST_STREAM1, ST_SASL, ST_STREAM2, ST_BIND, ST_ONLINE };

#define MAX_ROOMS 32
#define MAX_UPLOADS 32
#define MAX_MUJI_CALLS 4
#define MAX_MUJI_PEERS 16

typedef struct {
    tri_core *core;
    char acctkey[96], id[24], target[256], ctype[160], geturl[1024];

    char deliver_key[96], deliver_target[128];
    unsigned char *data; size_t len;
} xup_t;

#define VSINK_PEND_CAP (VP8_MAX_FRAME + 4096)

#define VDEC_W 480
#define VDEC_H 360
#define VDEC_FRAME ((VDEC_W) * (VDEC_H) * 4)
#define VDEC_PIPE  (1 << 20)
typedef struct {
    int   pid;
    int   in_fd, out_fd;
    int   started, failed;
    int   is_h264;
    int   ivf_hdr;
    uint32_t ivf_ts;
    uint8_t *pend; int pend_len, pend_off;
    uint8_t *frame; int frame_len;
    int   which;
    int   dec_w, dec_h;
    int   respawns;
    char  errlog[80];
} vsink;

#ifdef TRI_MUJI_MESH

#define MAX_PEERS MAX_MUJI_PEERS
typedef struct mesh_peer {
    account_t *a;
    int   active;
    char  room[256];
    char  full[320];
    jingle_session js;
    ice_agent *ice;
    int   ice_sent, ice_connected;
    dtls_srtp *dtls;
    int   dtls_started, dtls_secured;
    srtp_ctx tx, rx;
    int   media_ready;
    OpusDecoder *dec;
    tri_audio_sink *play;
    int   mix_off;
    uint16_t rtp_seq; uint32_t rtp_ts, rtp_ssrc; int rtp_pt;
    unsigned jseq;

    int   has_video;
    srtp_ctx tx_v, rx_v;
    uint16_t vseq; uint32_t vts, vssrc; int vid_pt;
    char  vcodec[8];
    tri_vdec_async *vdec; int vdec_tried;
    vsink vrx;
    vp8_reasm *vrx_vp8; h264_depacketizer *vrx_h264;
    uint16_t vrx_last_seq; int vrx_have_seq; uint32_t vrx_peer_ssrc;
    int   vrx_want_key; double vrx_pli_last;
    int   vwhich;
    int   muted;
    double last_talk;
} mesh_peer;
#endif

typedef struct {
    char host[256], port[8], node[128], pass[160], resource[64], domain[256];
    char autojoin[256];
    int  state;
    tri_resolve *resolve;
    int  tls;
    int  secured;
    char rbuf[131072];
    size_t rlen;
    char rooms[MAX_ROOMS][256];
    int  nrooms;
    struct { char id[24], target[256]; } pj[8];
    int  npj;
    struct { char target[256], id[24]; } lastsent[16];
    int  nlastsent;
    char upload_service[256];
    char upload_ns[48];
    xup_t *pend[MAX_UPLOADS];
    int  npend;
    double last_ka;
    double last_selfping;
    double last_faketype;
    omemo_store_t *omemo;

    struct omemo_pending {
        int active;
        unsigned seq;
        double started;
        char target[256], body[1500];
        uint32_t devices[8]; int ndev;
        omemo_bundle_t bundles[8];
        int have[8], outstanding;
    } opend[2];
    unsigned omemo_seq;
    double omemo_last_flush;
    char jid[256];

    char turn_host[128], turn_user[192], turn_pass[192];
    int  turn_port;
    jingle_session call;
    unsigned jingle_seq;
    ice_agent *ice;
    int  ice_sent;
    int  ice_connected;
    dtls_srtp *dtls;
    int  dtls_started;
    int  dtls_secured;
    double dtls_dbg_last;

    srtp_ctx srtp_tx, srtp_rx;
    int  media_ready;
    OpusEncoder *oenc;
    OpusDecoder *odec;
    tri_audio_sink *play;
    tri_audio_source *mic;
    int16_t mic_acc[960]; int mic_n;

    int16_t *sb_pcm; size_t sb_n, sb_pos; double sb_start; int sb_playing;

    int  want_video;
    srtp_ctx srtp_tx_v;
    int  vid_sending;
    FILE *vid_pipe; int vid_fd;

    int  vid_pid, vid_in_fd;
    uint8_t *vid_raw; int vid_raw_cap, vid_raw_len, vid_raw_off;
    uint8_t *vid_selfprev;
    double vid_grab_last;
#ifdef TRI_X11
    x11cap *x11;
#endif
    ivf_reader *vid_ivf;
    h264_reader *vid_h264;
    char vid_codec[8];
    uint16_t vrtp_seq; uint32_t vrtp_ts, vrtp_ssrc; int vid_pt;
    int  vid_frames;
    double vid_dbg_last;
    double vid_key_last;

    uint8_t *pace_q; uint16_t *pace_len;
    int pace_head, pace_count, pace_dropped;
    double pace_budget, pace_last, pace_rate;
    char vid_errlog[80];

    srtp_ctx srtp_rx_v;
    vsink vrx;
    vsink vtx_prev; int vtx_prev_on;

    tri_vdec_async *vrx_dec, *vtx_dec; int vrx_dec_tried, vtx_dec_tried;
    uint8_t *vtx_nalbuf; int vtx_nalcap;
    vp8_reasm *vrx_vp8;
    h264_depacketizer *vrx_h264;
    uint16_t vrx_last_seq; int vrx_have_seq;
    uint32_t vrx_peer_ssrc;
    int  vrx_want_key;
    double vrx_pli_last;
    int  vrx_frames, vrx_dropped;
    uint16_t rtp_seq; uint32_t rtp_ts, rtp_ssrc;
    int  rtp_pt;
    double last_media;
    int  rx_pkts, rx_authfail, rx_decoded, rx_decfail;
    double media_dbg_last;

    char jmi_id[64];
    char jmi_peer[256];
    int  jmi_out;
    int  jmi_in;
    int  auto_accept;

    struct muji_state {
        char room[256];
        int  active;
        int  video;
        struct { char nick[64]; int video; } peer[MAX_MUJI_PEERS];
        int  npeer;
    } muji[MAX_MUJI_CALLS];
#ifdef TRI_MUJI_MESH
    mesh_peer mesh[MAX_PEERS];
    OpusEncoder *mesh_enc;
    int  mesh_capturing;
    int  mesh_mic_muted;
    int  mesh_mixed;
    tri_audio_sink *mesh_mix_play;
    int32_t mesh_mix_acc[5760];
    int  mesh_mix_fill;
    double mesh_mix_last;
    int  mesh_vwhich_next;
    int  mesh_video_src;
#endif
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
} xp_priv;

#define OMEMO_DEVICELIST_NODE OMEMO_NS ".devicelist"
#define OMEMO_BUNDLES_PREFIX  OMEMO_NS ".bundles:"

static double now_s(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

static void emit(account_t *a, tri_event_kind k, const char *target, const char *text) {
    tri_event_t ev = { k, tri_account_key(a), target, text, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}
static void up_emit(account_t *a, xup_t *ctx, tri_event_kind k, const char *text);

static void call_signal(account_t *a, const char *state, const char *peerbare, int has_video) {
    tri_event_t ev = { TRI_EV_CALL, tri_account_key(a), peerbare, state, has_video ? "video" : "audio", 0, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static void muji_signal(account_t *a, const char *state, const char *room, int has_video) {
    tri_event_t ev = { TRI_EV_CALL, tri_account_key(a), room, state, has_video ? "groupvideo" : "group", 0, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static ssize_t xs_raw_write(xp_priv *p, int fd, const char *b, size_t n) {
    return p->secured ? wolfSSL_write(p->ssl, b, n) : write(fd, b, n);
}
static int xs_send(account_t *a, const char *s) {
    xp_priv *p = tri_account_priv(a);
    size_t n = strlen(s);
    if (xs_raw_write(p, tri_account_fd(a), s, n) != (ssize_t)n)
        return tri_set_error("xmpp: write failed on '%s'", tri_account_name(a));
    return 0;
}
static int xs_sendf(account_t *a, const char *fmt, ...) {
    char buf[2048]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    return xs_send(a, buf);
}

static int xml_attr(const char *s, const char *name, char *out, size_t osz) {
    char needle[64]; snprintf(needle, sizeof needle, "%s=", name);
    const char *q = s;
    while ((q = strstr(q, needle))) {
        if (q == s || q[-1] == ' ' || q[-1] == '<') {
            q += strlen(needle);
            char quote = *q++;
            if (quote != '"' && quote != '\'') continue;
            const char *e = strchr(q, quote);
            if (!e) return 0;
            size_t L = (size_t)(e - q); if (L >= osz) L = osz - 1;
            memcpy(out, q, L); out[L] = '\0';
            return 1;
        }
        q += strlen(needle);
    }
    return 0;
}
static void xml_unescape(char *s) {
    char *o = s;
    for (char *i = s; *i; ) {
        if (*i == '&') {
            if (!strncmp(i, "&lt;", 4))   { *o++ = '<'; i += 4; }
            else if (!strncmp(i, "&gt;", 4))   { *o++ = '>'; i += 4; }
            else if (!strncmp(i, "&amp;", 5))  { *o++ = '&'; i += 5; }
            else if (!strncmp(i, "&quot;", 6)) { *o++ = '"'; i += 6; }
            else if (!strncmp(i, "&apos;", 6)) { *o++ = '\''; i += 6; }
            else if (i[1] == '#') {
                const char *d = i + 2; int hex = (*d == 'x' || *d == 'X'); if (hex) d++;
                long cp = 0; const char *ds = d;
                while (*d && *d != ';') {
                    int v; if (*d >= '0' && *d <= '9') v = *d - '0';
                    else if (hex && (*d|32) >= 'a' && (*d|32) <= 'f') v = (*d|32) - 'a' + 10;
                    else { cp = -1; break; }
                    cp = cp * (hex ? 16 : 10) + v; d++;
                }
                if (cp < 0 || d == ds || *d != ';' || cp > 0x10FFFF) { *o++ = *i++; }
                else {
                    i = (char *)(d + 1);
                    if (cp < 0x80)         *o++ = (char)cp;
                    else if (cp < 0x800)  { *o++ = (char)(0xC0 | (cp >> 6)); *o++ = (char)(0x80 | (cp & 0x3F)); }
                    else if (cp < 0x10000){ *o++ = (char)(0xE0 | (cp >> 12)); *o++ = (char)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (char)(0x80 | (cp & 0x3F)); }
                    else                  { *o++ = (char)(0xF0 | (cp >> 18)); *o++ = (char)(0x80 | ((cp >> 12) & 0x3F)); *o++ = (char)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (char)(0x80 | (cp & 0x3F)); }
                }
            }
            else *o++ = *i++;
        } else *o++ = *i++;
    }
    *o = '\0';
}
static int xml_text(const char *s, const char *tag, char *out, size_t osz) {
    char open[32]; snprintf(open, sizeof open, "<%s", tag);
    char close[32]; snprintf(close, sizeof close, "</%s>", tag);
    size_t olen = strlen(open);
    const char *t = s; int saw_empty = 0;
    while ((t = strstr(t, open))) {
        char nxt = t[olen];
        if (nxt != ' ' && nxt != '\t' && nxt != '\n' && nxt != '\r' && nxt != '>' && nxt != '/') { t += olen; continue; }
        const char *gt = strchr(t, '>');
        if (!gt) return 0;

        if (gt[-1] == '/') { saw_empty = 1; t = gt + 1; continue; }
        const char *start = gt + 1;
        const char *e = strstr(start, close);
        if (!e) return 0;
        size_t L = (size_t)(e - start); if (L >= osz) L = osz - 1;
        memcpy(out, start, L); out[L] = '\0';
        xml_unescape(out);
        return 1;
    }
    if (saw_empty) { out[0] = '\0'; return 1; }
    return 0;
}
static void xml_escape(const char *in, char *out, size_t osz) {
    size_t o = 0;
    for (; *in && o + 6 < osz; in++) {
        switch (*in) {
            case '<': memcpy(out + o, "&lt;", 4); o += 4; break;
            case '>': memcpy(out + o, "&gt;", 4); o += 4; break;
            case '&': memcpy(out + o, "&amp;", 5); o += 5; break;
            case '"': memcpy(out + o, "&quot;", 6); o += 6; break;
            case '\'': memcpy(out + o, "&apos;", 6); o += 6; break;
            default: out[o++] = *in;
        }
    }
    out[o] = '\0';
}
static void bare_jid(const char *full, char *out, size_t osz) {
    snprintf(out, osz, "%s", full);
    char *slash = strchr(out, '/'); if (slash) *slash = '\0';
}

#define DISCO_NODE     "https://cyberix.net/trichat"
#define DISCO_IDENTITY "client/pc//Trichat"
static const char *const DISCO_FEATURES[] = {
    "http://jabber.org/protocol/chatstates",
    "http://jabber.org/protocol/disco#info",
    "urn:xmpp:jingle-message:0",
    "urn:xmpp:jingle:1",
    "urn:xmpp:jingle:apps:dtls:0",
    "urn:xmpp:jingle:apps:rtp:1",
    "urn:xmpp:jingle:apps:rtp:audio",
    "urn:xmpp:jingle:muji:0",
    "urn:xmpp:jingle:transports:ice-udp:1",
    "urn:xmpp:receipts",
};
#define NDISCO ((int)(sizeof DISCO_FEATURES / sizeof DISCO_FEATURES[0]))

static void caps_ver(char *out, size_t osz) {
    char S[1024]; int n = snprintf(S, sizeof S, "%s<", DISCO_IDENTITY);
    for (int i = 0; i < NDISCO && n < (int)sizeof S - 1; i++) n += snprintf(S + n, sizeof S - (size_t)n, "%s<", DISCO_FEATURES[i]);
    uint8_t h[20]; wc_Sha sha;
    if (wc_InitSha(&sha) != 0) { out[0] = '\0'; return; }
    wc_ShaUpdate(&sha, (const byte *)S, (word32)n); wc_ShaFinal(&sha, h); wc_ShaFree(&sha);
    if (osz >= 29) tri_b64enc(h, 20, out); else out[0] = '\0';
}

static void send_disco_info(account_t *a, const char *to, const char *id, const char *node) {
    char fesc[300], nodeattr[200] = "";
    xml_escape(to, fesc, sizeof fesc);
    if (node && node[0]) { char nesc[160]; xml_escape(node, nesc, sizeof nesc); snprintf(nodeattr, sizeof nodeattr, " node='%s'", nesc); }
    char q[1200]; int n = snprintf(q, sizeof q,
        "<iq type='result' to='%s' id='%s'><query xmlns='http://jabber.org/protocol/disco#info'%s>"
        "<identity category='client' type='pc' name='Trichat'/>", fesc, id, nodeattr);
    for (int i = 0; i < NDISCO && n < (int)sizeof q - 64; i++) n += snprintf(q + n, sizeof q - (size_t)n, "<feature var='%s'/>", DISCO_FEATURES[i]);
    snprintf(q + n, sizeof q - (size_t)n, "</query></iq>");
    xs_send(a, q);
}

static void xmpp_teardown(account_t *a, const char *why);
static void handle_jingle(account_t *a, const char *s, const char *iq_id);
static void handle_jmi(account_t *a, const char *s);
static void call_end_ice(account_t *a);
#ifdef TRI_MUJI_MESH
static void mesh_fanout_audio(account_t *a, const int16_t *pcm, int samples);
static void mesh_maybe_initiate(account_t *a, const char *room, const char *peer_nick);
static void mesh_end_peer_full(account_t *a, const char *full);
static void mesh_end_room(account_t *a, const char *room);
static int  mesh_route_jingle(account_t *a, const char *from, const jingle_session *js, const char *action);
static void mesh_teardown_all(account_t *a);
static int  mesh_video_active(xp_priv *p);
static void mesh_video_send(account_t *a, const uint8_t *payload, int plen, int marker, uint32_t ts);
static void mesh_video_start(account_t *a);
static void mesh_video_stop(account_t *a);
#endif

static void fatal_fail(account_t *a, const char *reason) {
    tri_set_error("%s", reason);
    xmpp_teardown(a, NULL);
    tri_account_notify_failed(a, reason);
}

static void send_stream_header(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    xs_sendf(a, "<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' "
                "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", p->domain);
}
static void send_auth(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    unsigned char raw[400]; int n = 0;
    raw[n++] = 0;
    n += snprintf((char *)raw + n, sizeof raw - n, "%s", p->node) + 1;
    n += snprintf((char *)raw + n, sizeof raw - n, "%s", p->pass);
    char enc[600]; tri_b64enc(raw, n, enc);
    xs_sendf(a, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>%s</auth>", enc);
}

static int xmpp_is_group(account_t *a, const char *target) {
    xp_priv *p = tri_account_priv(a);
    if (!p || !target || !target[0]) return 0;
    char bare[256]; snprintf(bare, sizeof bare, "%s", target);
    char *slash = strchr(bare, '/'); if (slash) *slash = '\0';
    for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], bare)) return 1;
    return 0;
}
static void do_muc_join(account_t *a, const char *room) {
    xp_priv *p = tri_account_priv(a);
    for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], room)) return;
    if (p->nrooms < MAX_ROOMS) snprintf(p->rooms[p->nrooms++], 256, "%s", room);

    const char *nick = tri_channel_nick(a, room);
    if (!nick[0]) nick = p->node;
    xs_sendf(a, "<presence to='%s/%s'><x xmlns='http://jabber.org/protocol/muc'/></presence>", room, nick);
    emit(a, TRI_EV_STATUS, room, "joining MUC");
}

#define MUJI_NS "urn:xmpp:jingle:muji:0"

static struct muji_state *muji_get(xp_priv *p, const char *room) {
    for (int i = 0; i < MAX_MUJI_CALLS; i++) if (!strcmp(p->muji[i].room, room)) return &p->muji[i];
    for (int i = 0; i < MAX_MUJI_CALLS; i++) if (!p->muji[i].room[0]) {
        snprintf(p->muji[i].room, sizeof p->muji[i].room, "%s", room); return &p->muji[i]; }
    return NULL;
}

static void muji_send_presence(account_t *a, const char *room, int video, int joining) {
    xp_priv *p = tri_account_priv(a);
    const char *nick = tri_channel_nick(a, room);
    if (!nick[0]) nick = p->node;
    if (!joining) {
        xs_sendf(a, "<presence to='%s/%s'><muji xmlns='" MUJI_NS "'/></presence>", room, nick);
        return;
    }
    const char *vc = video
        ? "<content name='video'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='video'/></content>" : "";
    xs_sendf(a, "<presence to='%s/%s'><muji xmlns='" MUJI_NS "'>"
                "<content name='voice'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></content>%s"
                "</muji></presence>", room, nick, vc);
}

static void muji_track(account_t *a, const char *room, const char *nick, const char *stanza, const char *type) {
    xp_priv *p = tri_account_priv(a);
    const char *self = tri_channel_nick(a, room);
    if (!self[0]) self = p->node;
    if (!strcmp(nick, self)) return;

    const char *muji = strstr(stanza, MUJI_NS);
    int prepared = 0, video = 0;
    if (muji && strcmp(type, "unavailable")) {
        prepared = strstr(muji, "<content") != NULL;
        video    = strstr(muji, "media='video'") != NULL;
    }

    struct muji_state *m = muji_get(p, room);
    if (!m) return;
    int idx = -1;
    for (int i = 0; i < m->npeer; i++) if (!strcmp(m->peer[i].nick, nick)) { idx = i; break; }
    if (prepared) {
        if (idx < 0) {
            if (m->npeer >= MAX_MUJI_PEERS) return;
            idx = m->npeer++;
            snprintf(m->peer[idx].nick, sizeof m->peer[idx].nick, "%s", nick);
        }
        m->peer[idx].video = video;
#ifdef TRI_MUJI_MESH
        mesh_maybe_initiate(a, room, nick);
#endif
    } else {
        if (idx < 0) { if (!m->active && m->npeer == 0) m->room[0] = '\0'; return; }
        m->peer[idx] = m->peer[--m->npeer];
#ifdef TRI_MUJI_MESH
        { char full[320]; snprintf(full, sizeof full, "%s/%s", room, nick); mesh_end_peer_full(a, full); }
#endif
    }

    char line[160];
    if (m->npeer > 0) snprintf(line, sizeof line, "[muji] %d participant%s ready in group call",
                               m->npeer, m->npeer == 1 ? "" : "s");
    else              snprintf(line, sizeof line, "[muji] group call ended");
    emit(a, TRI_EV_STATUS, room, line);
    if (m->npeer == 0 && !m->active) m->room[0] = '\0';
}

static int muji_call(account_t *a, const char *room, int action) {
    xp_priv *p = tri_account_priv(a);
    struct muji_state *m = muji_get(p, room);
    if (!m) return tri_set_error("xmpp: too many group calls at once (max %d)", MAX_MUJI_CALLS);

    if (m->active && (action == TRI_CALL_VIDEO || action == TRI_CALL_SCREENSHARE || action == TRI_CALL_VIDEO_STOP)) {
#ifdef TRI_MUJI_MESH
        if (action == TRI_CALL_VIDEO_STOP) {
            mesh_video_stop(a);
            emit(a, TRI_EV_STATUS, room, "[muji] stopped sending video");
            muji_signal(a, "active", room, 0);
            return 0;
        }
        int src = (action == TRI_CALL_SCREENSHARE) ? 2 : 1;
        if (p->vid_sending && p->mesh_video_src != src) mesh_video_stop(a);
        p->mesh_video_src = src;
        mesh_video_start(a);
        emit(a, TRI_EV_STATUS, room,
             src == 2 ? "[muji] screensharing to the room" : "[muji] sending video to the room");
        muji_signal(a, "active", room, 1);
        return 0;
#else
        return tri_set_error("xmpp: group-call video needs the mesh build");
#endif
    }

    if (action == TRI_CALL_START || action == TRI_CALL_VIDEO || action == TRI_CALL_SCREENSHARE) {
        m->active = 1;
        m->video  = 0;
        muji_send_presence(a, room, 0, 1);
#ifdef TRI_MUJI_MESH
        p->mesh_video_src = 0;
        for (int i = 0; i < m->npeer; i++) mesh_maybe_initiate(a, room, m->peer[i].nick);
        char msg[320]; snprintf(msg, sizeof msg, "[muji] joined group call (%d other%s ready) - meshing audio",
                                m->npeer, m->npeer == 1 ? "" : "s");
#else
        char msg[320]; snprintf(msg, sizeof msg,
            "[muji] joined group call (%d other%s ready) - mesh media not wired yet, signaling only",
            m->npeer, m->npeer == 1 ? "" : "s");
#endif
        emit(a, TRI_EV_STATUS, room, msg);
        muji_signal(a, "active", room, 0);
        return 0;
    }
    if (action == TRI_CALL_HANGUP) {
        if (!m->active) return tri_set_error("xmpp: no group call to leave in %s", room);
        m->active = 0; m->video = 0;
        muji_send_presence(a, room, 0, 0);
#ifdef TRI_MUJI_MESH
        mesh_end_room(a, room);
#endif
        emit(a, TRI_EV_STATUS, room, "[muji] left group call");
        muji_signal(a, "ended", room, 0);
        if (m->npeer == 0) m->room[0] = '\0';
        return 0;
    }
    if (action == TRI_CALL_VIDEO_STOP) return tri_set_error("xmpp: no group call to stop video in %s", room);
    return tri_set_error("xmpp: group call: only start/video/screenshare/stop/hangup supported");
}

#ifdef TRI_MUJI_MESH
static int muji_call_peers(account_t *a, const char *room, void *out_v, int cap) {
    xp_priv *p = tri_account_priv(a);
    tri_call_peer_t *out = out_v;
    double now = now_s();
    int n = 0;
    for (int i = 0; i < MAX_PEERS && n < cap; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active || strcmp(mp->room, room)) continue;
        tri_call_peer_t *e = &out[n++];
        memset(e, 0, sizeof *e);
        const char *nick = strrchr(mp->full, '/'); nick = nick ? nick + 1 : mp->full;
        snprintf(e->nick, sizeof e->nick, "%s", nick);
        snprintf(e->full, sizeof e->full, "%s", mp->full);
        e->connected  = mp->media_ready;
        e->has_video  = mp->has_video;
        e->video_slot = mp->vwhich >= 2 ? mp->vwhich : 0;
        e->talking    = mp->last_talk > 0 && (now - mp->last_talk) < 0.4;
        e->muted      = mp->muted;
    }
    return n;
}
static int muji_call_peer_mute(account_t *a, const char *room, const char *full, int muted) {
    xp_priv *p = tri_account_priv(a);
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (mp->active && !strcmp(mp->room, room) && !strcmp(mp->full, full)) { mp->muted = muted ? 1 : 0; return 0; }
    }
    return tri_set_error("xmpp: no such group-call peer '%s'", full ? full : "");
}
#else
static int muji_call_peers(account_t *a, const char *room, void *out, int cap) {
    (void)a; (void)room; (void)out; (void)cap; return 0;
}
static int muji_call_peer_mute(account_t *a, const char *room, const char *full, int muted) {
    (void)a; (void)room; (void)full; (void)muted;
    return tri_set_error("xmpp: this build has no group-call mesh");
}
#endif

static void publish_bookmark(account_t *a, const char *room) {
    xp_priv *p = tri_account_priv(a);
    xs_sendf(a, "<iq type='set' id='bmput'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                "<publish node='urn:xmpp:bookmarks:1'><item id='%s'>"
                "<conference xmlns='urn:xmpp:bookmarks:1' autojoin='true'><nick>%s</nick></conference>"
                "</item></publish><publish-options><x xmlns='jabber:x:data' type='submit'>"
                "<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>"
                "<field var='pubsub#persist_items'><value>true</value></field>"
                "<field var='pubsub#max_items'><value>max</value></field>"
                "<field var='pubsub#access_model'><value>whitelist</value></field>"
                "</x></publish-options></pubsub></iq>", room, p->node);
}
static void retract_bookmark(account_t *a, const char *room) {
    xs_sendf(a, "<iq type='set' id='bmdel'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                "<retract node='urn:xmpp:bookmarks:1'><item id='%s'/></retract></pubsub></iq>", room);
}

static void omemo_announce(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->omemo) p->omemo = omemo_store_open(tri_account_key(a));
    if (!p->omemo) { emit(a, TRI_EV_STATUS, NULL, "OMEMO: store unavailable (encryption off)"); return; }
    uint32_t dev = omemo_store_device_id(p->omemo);
    char bundle[8192];
    if (omemo_store_bundle_xml(p->omemo, bundle, sizeof bundle) == 0) {
        size_t need = strlen(bundle) + 700;
        char *iq = malloc(need);
        if (iq) {
            snprintf(iq, need,
                "<iq type='set' id='omemo_bundle'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                "<publish node='%s%u'><item id='current'>%s</item></publish>"
                "<publish-options><x xmlns='jabber:x:data' type='submit'>"
                "<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>"
                "<field var='pubsub#access_model'><value>open</value></field>"
                "</x></publish-options></pubsub></iq>",
                OMEMO_BUNDLES_PREFIX, dev, bundle);
            xs_send(a, iq);
            free(iq);
        }
    }
    xs_sendf(a, "<iq type='get' id='omemo_dl'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                "<items node='%s'/></pubsub></iq>", OMEMO_DEVICELIST_NODE);
    char fp[80];
    if (omemo_store_fingerprint(p->omemo, fp, sizeof fp) == 0) {
        char m[160]; snprintf(m, sizeof m, "OMEMO ready (device %u, fingerprint %.16s...)", dev, fp);
        emit(a, TRI_EV_STATUS, NULL, m);
    }
}

static void omemo_publish_devicelist(account_t *a, uint32_t *ids, int n) {
    xp_priv *p = tri_account_priv(a);
    uint32_t self = omemo_store_device_id(p->omemo);
    int have = 0; for (int i = 0; i < n; i++) if (ids[i] == self) have = 1;
    if (have && n > 0) return;
    if (n < 64) ids[n++] = self;
    char list[1024];
    if (omemo_devicelist_build(ids, n, list, sizeof list) != 0) return;
    xs_sendf(a, "<iq type='set' id='omemo_dlpub'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                "<publish node='%s'><item id='current'>%s</item></publish>"
                "<publish-options><x xmlns='jabber:x:data' type='submit'>"
                "<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>"
                "<field var='pubsub#access_model'><value>open</value></field>"
                "</x></publish-options></pubsub></iq>",
             OMEMO_DEVICELIST_NODE, list);
}

static int omemo_send_stanza(account_t *a, const char *target, const char *enc) {
    static unsigned mc = 0;
    char tesc[300]; xml_escape(target, tesc, sizeof tesc);
    size_t need = strlen(enc) + sizeof tesc + 300;
    char *msg = malloc(need); if (!msg) return tri_set_error("xmpp: out of memory (omemo send)");
    snprintf(msg, need, "<message id='om%u' to='%s' type='chat'>%s"
             "<encryption xmlns='urn:xmpp:eme:0' namespace='%s'/><store xmlns='urn:xmpp:hints'/>"
             "<body>[This message is OMEMO-encrypted.]</body></message>", ++mc, tesc, enc, OMEMO_NS);
    int rc = xs_send(a, msg);
    free(msg);
    return rc;
}

static void omemo_finalize_send(account_t *a, struct omemo_pending *pd) {
    xp_priv *p = tri_account_priv(a);
    char enc[8192];
    if (p->omemo && omemo_store_encrypt(p->omemo, pd->target, pd->devices, pd->bundles, pd->ndev,
                                        (const uint8_t *)pd->body, strlen(pd->body), enc, sizeof enc) == 0) {
        tri_log(tri_account_core(a), "omemo: encrypted to %d device(s) of %s", pd->ndev, pd->target);
        omemo_send_stanza(a, pd->target, enc);
    } else {
        char esc[1600]; xml_escape(pd->body, esc, sizeof esc);
        xs_sendf(a, "<message to='%s' type='chat'><body>%s</body></message>", pd->target, esc);
        emit(a, TRI_EV_STATUS, pd->target, "OMEMO unavailable for this contact - sent in cleartext");
    }
    pd->active = 0;
}
static struct omemo_pending *omemo_pending_by_seq(xp_priv *p, unsigned seq) {
    for (int i = 0; i < (int)(sizeof p->opend / sizeof p->opend[0]); i++)
        if (p->opend[i].active && p->opend[i].seq == seq) return &p->opend[i];
    return NULL;
}
static int xmpp_omemo_own_fingerprint(account_t *a, char *out, size_t n) {
    xp_priv *p = tri_account_priv(a);
    if (!p || !p->omemo) return tri_set_error("xmpp: OMEMO not initialised on this account");
    char fp[80]; omemo_store_fingerprint(p->omemo, fp, sizeof fp);
    snprintf(out, n, "%u %s", omemo_store_device_id(p->omemo), fp);
    return 0;
}
static int xmpp_omemo_devices(account_t *a, const char *target, tri_omemo_device_t *out, int cap) {
    xp_priv *p = tri_account_priv(a);
    if (!p || !p->omemo) return tri_set_error("xmpp: OMEMO not initialised on this account");
    char bare[256]; bare_jid(target, bare, sizeof bare);
    uint32_t devs[32]; char fps[32][65]; signed char trust[32];
    int nd = omemo_store_peer_fingerprints(p->omemo, bare, devs, fps, trust, cap < 32 ? cap : 32);
    for (int i = 0; i < nd; i++) {
        out[i].device_id = devs[i];
        snprintf(out[i].fingerprint, sizeof out[i].fingerprint, "%s", fps[i]);
        out[i].trust = trust[i];
    }
    return nd;
}
static int xmpp_omemo_set_trust(account_t *a, const char *target, unsigned device_id, int trust) {
    xp_priv *p = tri_account_priv(a);
    if (!p || !p->omemo) return tri_set_error("xmpp: OMEMO not initialised on this account");
    char bare[256]; bare_jid(target, bare, sizeof bare);
    if (omemo_store_set_trust(p->omemo, bare, device_id, trust) != 0)
        return tri_set_error("xmpp: no OMEMO session with device %u yet", device_id);
    return 0;
}

static int omemo_begin_send(account_t *a, const char *target, const char *body) {
    xp_priv *p = tri_account_priv(a);
    struct omemo_pending *pd = NULL;
    for (int i = 0; i < (int)(sizeof p->opend / sizeof p->opend[0]); i++) if (!p->opend[i].active) { pd = &p->opend[i]; break; }
    if (!pd) return -1;
    memset(pd, 0, sizeof *pd);
    pd->active = 1; pd->seq = ++p->omemo_seq; pd->started = now_s();
    snprintf(pd->target, sizeof pd->target, "%s", target);
    snprintf(pd->body, sizeof pd->body, "%s", body);
    char tesc[300]; xml_escape(target, tesc, sizeof tesc);
    xs_sendf(a, "<iq type='get' id='omemo_dq%u' to='%s'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                "<items node='%s'/></pubsub></iq>", pd->seq, tesc, OMEMO_DEVICELIST_NODE);
    return 0;
}

static void go_online(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    p->state = ST_ONLINE;
    tri_account_set_state(a, TRI_CS_ONLINE);
    emit(a, TRI_EV_STATUS, NULL, "logged in");
    { char ver[40]; caps_ver(ver, sizeof ver);
      xs_sendf(a, "<presence><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='%s' ver='%s'/></presence>", DISCO_NODE, ver); }
    xs_send(a, "<iq type='get' id='rost1'><query xmlns='jabber:iq:roster'/></iq>");
    xs_send(a, "<iq type='get' id='bm1'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
               "<items node='urn:xmpp:bookmarks:1'/></pubsub></iq>");
    xs_send(a, "<iq type='set' id='mam1'><query xmlns='urn:xmpp:mam:2'>"
               "<set xmlns='http://jabber.org/protocol/rsm'><max>50</max><before/></set></query></iq>");
    xs_send(a, "<iq type='set' id='carbons1'><enable xmlns='urn:xmpp:carbons:2'/></iq>");

    xs_sendf(a, "<iq type='get' id='disco_srv' to='%s'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>", p->domain);
    xs_sendf(a, "<iq type='get' id='di_self' to='%s'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>", p->domain);
    xs_sendf(a, "<iq type='get' id='extdisco' to='%s'><services xmlns='urn:xmpp:extdisco:2'/></iq>", p->domain);
    if (p->autojoin[0]) { do_muc_join(a, p->autojoin); publish_bookmark(a, p->autojoin); }
    omemo_announce(a);
}

static void tls_pump(account_t *a);
static void xmpp_put_done(void *ud, int ok, int status, const char *body, size_t len, const char *ctype);

static long long iso8601_epoch(const char *s) {
    int Y, Mo, D, H, Mi, Se;
    if (sscanf(s, "%d-%d-%dT%d:%d:%d", &Y, &Mo, &D, &H, &Mi, &Se) != 6) return 0;
    int y = Y - (Mo <= 2);
    long long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (Mo + (Mo > 2 ? -3 : 9)) + 2) / 5 + D - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = era * 146097 + (long long)doe - 719468;
    return days * 86400LL + H * 3600 + Mi * 60 + Se;
}

static int forwarded_message(const char *s, char *from, size_t fn, char *to, size_t tn,
                             char *body, size_t bn, long long *ts) {
    const char *fwd = strstr(s, "<forwarded"); if (!fwd) return 0;
    *ts = 0;
    const char *dl = strstr(fwd, "<delay");
    if (dl) { char stamp[40]; if (xml_attr(dl, "stamp", stamp, sizeof stamp)) *ts = iso8601_epoch(stamp); }
    const char *im = strstr(fwd, "<message"); if (!im) return 0;
    from[0] = to[0] = body[0] = '\0';
    xml_attr(im, "from", from, fn);
    xml_attr(im, "to", to, tn);
    if (!xml_text(im, "body", body, bn) || !body[0]) return 0;
    return 1;
}

static void handle_mam_result(account_t *a, const char *s) {
    xp_priv *p = tri_account_priv(a);
    char from[256], to[256], body[1500]; long long ts;
    if (!forwarded_message(s, from, sizeof from, to, sizeof to, body, sizeof body, &ts)) return;
    char mybare[300]; snprintf(mybare, sizeof mybare, "%s@%s", p->node, p->domain);
    char fbare[256]; bare_jid(from, fbare, sizeof fbare);
    int outgoing = !strcasecmp(fbare, mybare);
    char peer[256]; bare_jid(outgoing ? to : from, peer, sizeof peer);
    for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], peer)) return;
    const char *nick = outgoing ? p->node : peer;

    const char *enc = strstr(s, "<encrypted");
    if (enc && strstr(s, OMEMO_NS)) {
        if (outgoing || !p->omemo) return;
        uint8_t pt[2048];
        int pl = omemo_store_decrypt(p->omemo, fbare, enc, pt, sizeof pt - 1);
        if (pl <= 0) return;
        pt[pl] = '\0';
        tri_event_t dev = { TRI_EV_MESSAGE, tri_account_key(a), peer, (const char *)pt, nick, ts, 1, 1 };
        tri_emit(tri_account_core(a), &dev);
        return;
    }
    tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), peer, body, nick, ts };
    tri_emit(tri_account_core(a), &ev);
}

static void handle_carbon(account_t *a, const char *s) {
    xp_priv *p = tri_account_priv(a);
    char mybare[300]; snprintf(mybare, sizeof mybare, "%s@%s", p->node, p->domain);
    char outer[256] = ""; xml_attr(s, "from", outer, sizeof outer);
    if (outer[0]) { char ob[256]; bare_jid(outer, ob, sizeof ob); if (strcasecmp(ob, mybare)) return; }
    int sent;
    if (strstr(s, "<received")) sent = 0;
    else if (strstr(s, "<sent")) sent = 1;
    else return;
    char from[256], to[256], body[1500]; long long ts;
    if (!forwarded_message(s, from, sizeof from, to, sizeof to, body, sizeof body, &ts)) return;
    char peer[256]; bare_jid(sent ? to : from, peer, sizeof peer);
    for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], peer)) return;
    const char *nick = sent ? p->node : peer;
    tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), peer, body, nick, ts };
    tri_emit(tri_account_core(a), &ev);
}

static void handle_stanza(account_t *a, char *s) {
    xp_priv *p = tri_account_priv(a);

    if (!strncmp(s, "<stream:features", 16)) {
        if (p->state == ST_STREAM0) {
            if (!p->tls) {
                if (strstr(s, "PLAIN")) { send_auth(a); p->state = ST_SASL; }
                else fatal_fail(a, "xmpp: server offers no SASL PLAIN");
            } else if (strstr(s, "starttls")) xs_send(a, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
            else fatal_fail(a, "xmpp: server offers no STARTTLS");
        } else if (p->state == ST_STREAM1) {
            if (strstr(s, "PLAIN")) { send_auth(a); p->state = ST_SASL; }
            else fatal_fail(a, "xmpp: server offers no SASL PLAIN");
        } else if (p->state == ST_STREAM2) {
            xs_sendf(a, "<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>%s</resource></bind></iq>", p->resource);
            p->state = ST_BIND;
        }
        return;
    }
    if (!strncmp(s, "<proceed", 8)) {
        p->state = ST_TLS_HS;
        static int inited = 0; if (!inited) { wolfSSL_Init(); inited = 1; }
        p->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        wolfSSL_CTX_set_verify(p->ctx, WOLFSSL_VERIFY_NONE, NULL);
        p->ssl = wolfSSL_new(p->ctx);
        wolfSSL_set_fd(p->ssl, tri_account_fd(a));
        tls_pump(a);
        return;
    }
    if (!strncmp(s, "<success", 8)) {
        p->state = ST_STREAM2;
        send_stream_header(a);
        return;
    }
    if (!strncmp(s, "<failure", 8)) {
        char reason[128] = "authentication failed";
        const char *lt = strchr(s + 8, '<');
        if (lt && lt[1] != '/') { sscanf(lt, "<%127[^/ >]", reason); }
        char msg[160]; snprintf(msg, sizeof msg, "xmpp: %s", reason);
        fatal_fail(a, msg);
        return;
    }
    if (!strncmp(s, "<iq", 3)) {
        char id[64] = "", type[16] = "";
        xml_attr(s, "id", id, sizeof id);
        xml_attr(s, "type", type, sizeof type);
        if (!strcmp(type, "set") && strstr(s, "<jingle")) { handle_jingle(a, s, id); return; }
        if (!strncmp(id, "sp:", 3)) {
            if (!strcmp(type, "error") && strstr(s, "not-acceptable")) {
                int ri = atoi(id + 3);
                if (ri >= 0 && ri < p->nrooms) {
                    char room[256]; snprintf(room, sizeof room, "%s", p->rooms[ri]);
                    for (int i = ri; i < p->nrooms - 1; i++) snprintf(p->rooms[i], 256, "%s", p->rooms[i + 1]);
                    p->nrooms--;
                    emit(a, TRI_EV_STATUS, room, "MUC dropped us - rejoining");
                    do_muc_join(a, room);
                }
            }
            return;
        }
        if (!strcmp(id, "bind1") && !strcmp(type, "result")) {
            char jid[256]; if (xml_text(s, "jid", jid, sizeof jid)) { snprintf(p->jid, sizeof p->jid, "%s", jid); char m[300]; snprintf(m, sizeof m, "bound as %s", jid); emit(a, TRI_EV_STATUS, NULL, m); }
            go_online(a);
            return;
        }
        if (!strcmp(id, "rost1") && !strcmp(type, "result")) {
            const char *it = s;
            while ((it = strstr(it, "<item"))) {
                const char *end = strchr(it, '>'); if (!end) break;
                char item[600]; size_t L = (size_t)(end - it) + 1; if (L >= sizeof item) L = sizeof item - 1;
                memcpy(item, it, L); item[L] = '\0';
                char jid[256]; if (xml_attr(item, "jid", jid, sizeof jid)) { char m[300]; snprintf(m, sizeof m, "contact: %s", jid); emit(a, TRI_EV_STATUS, jid, m); }
                it = end + 1;
            }
            return;
        }
        if (!strcmp(id, "omemo_dl") && p->omemo) {
            uint32_t ids[64];
            int n = omemo_devicelist_parse(s, ids, 64);
            omemo_publish_devicelist(a, ids, n < 0 ? 0 : n);
            return;
        }
        if (!strncmp(id, "omemo_dq", 8) && p->omemo) {
            unsigned seq = 0; sscanf(id + 8, "%u", &seq);
            struct omemo_pending *pd = omemo_pending_by_seq(p, seq);
            if (!pd) return;
            uint32_t ids[16]; int n = omemo_devicelist_parse(s, ids, 16);
            if (n <= 0) { omemo_finalize_send(a, pd); return; }
            pd->ndev = 0; pd->outstanding = 0;
            for (int i = 0; i < n && pd->ndev < 8; i++) {
                int di = pd->ndev++; pd->devices[di] = ids[i];
                if (omemo_store_has_session(p->omemo, pd->target, ids[i])) { pd->have[di] = 1; continue; }
                pd->outstanding++;
                char tesc[300]; xml_escape(pd->target, tesc, sizeof tesc);
                xs_sendf(a, "<iq type='get' id='omemo_bq%u_%d' to='%s'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                            "<items node='%s%u'/></pubsub></iq>", seq, di, tesc, OMEMO_BUNDLES_PREFIX, ids[i]);
            }
            if (pd->outstanding == 0) omemo_finalize_send(a, pd);
            return;
        }
        if (!strncmp(id, "omemo_bq", 8) && p->omemo) {
            unsigned seq = 0; int idx = -1; sscanf(id + 8, "%u_%d", &seq, &idx);
            struct omemo_pending *pd = omemo_pending_by_seq(p, seq);
            if (!pd || idx < 0 || idx >= pd->ndev) return;
            if (!strcmp(type, "result") && omemo_bundle_parse(s, &pd->bundles[idx]) == 0) pd->have[idx] = 1;
            if (pd->outstanding > 0) pd->outstanding--;
            if (pd->outstanding == 0) omemo_finalize_send(a, pd);
            return;
        }
        if (!strcmp(id, "bm1") && !strcmp(type, "result")) {
            const char *it = s;
            while ((it = strstr(it, "<item"))) {
                const char *gt = strchr(it, '>'); if (!gt) break;
                const char *next = strstr(gt, "</item>");
                char item[700];
                size_t span = next ? (size_t)(next - it) : strlen(it);
                if (span >= sizeof item) span = sizeof item - 1;
                memcpy(item, it, span); item[span] = '\0';
                char room[256];
                if (xml_attr(item, "id", room, sizeof room) &&
                    (strstr(item, "autojoin='true'") || strstr(item, "autojoin=\"true\"") || strstr(item, "autojoin='1'")))
                    do_muc_join(a, room);
                it = next ? next + 7 : gt + 1;
            }
            return;
        }
        if (!strncmp(id, "jchk", 4)) {
            int idx = -1; for (int i = 0; i < p->npj; i++) if (!strcmp(p->pj[i].id, id)) { idx = i; break; }
            if (idx < 0) return;
            char target[256]; snprintf(target, sizeof target, "%s", p->pj[idx].target);
            for (int i = idx; i < p->npj - 1; i++) p->pj[i] = p->pj[i + 1];
            p->npj--;

            int is_muc = !strcmp(type, "result") &&
                         (strstr(s, "http://jabber.org/protocol/muc") ||
                          strstr(s, "category='conference'") || strstr(s, "category=\"conference\""));
            if (is_muc) { do_muc_join(a, target); publish_bookmark(a, target); }
            else        { emit(a, TRI_EV_STATUS, target, "chat ready"); }
            return;
        }
        if (!strcmp(id, "disco_srv") && !strcmp(type, "result")) {
            const char *it = s;
            while ((it = strstr(it, "<item"))) {
                const char *gt = strchr(it, '>'); if (!gt) break;
                char item[600]; size_t L = (size_t)(gt - it) + 1; if (L >= sizeof item) L = sizeof item - 1;
                memcpy(item, it, L); item[L] = '\0';
                char jid[256];
                if (xml_attr(item, "jid", jid, sizeof jid))
                    xs_sendf(a, "<iq type='get' id='di1' to='%s'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>", jid);
                it = gt + 1;
            }
            return;
        }
        if (!strcmp(id, "extdisco") && !strcmp(type, "result")) {
            const char *it = s;
            while ((it = strstr(it, "<service"))) {
                const char *gt = strchr(it, '>'); if (!gt) break;
                char svc[600]; size_t L = (size_t)(gt - it) + 1; if (L >= sizeof svc) L = sizeof svc - 1;
                memcpy(svc, it, L); svc[L] = '\0';
                it = gt + 1;
                char stype[16] = "", transport[16] = "";
                xml_attr(svc, "type", stype, sizeof stype);
                xml_attr(svc, "transport", transport, sizeof transport);
                if (strcmp(stype, "turn")) continue;
                if (transport[0] && strcasecmp(transport, "udp")) continue;
                char host[128] = "", port[8] = "";
                xml_attr(svc, "host", host, sizeof host);
                xml_attr(svc, "port", port, sizeof port);
                if (!host[0]) continue;
                xml_unescape(host);
                xml_attr(svc, "username", p->turn_user, sizeof p->turn_user);
                xml_attr(svc, "password", p->turn_pass, sizeof p->turn_pass);
                xml_unescape(p->turn_user); xml_unescape(p->turn_pass);
                snprintf(p->turn_host, sizeof p->turn_host, "%s", host);
                p->turn_port = port[0] ? atoi(port) : 3478;
                char m[200]; snprintf(m, sizeof m, "TURN relay available (%s:%d)", p->turn_host, p->turn_port);
                emit(a, TRI_EV_STATUS, NULL, m);
                break;
            }
            return;
        }
        if (!strcmp(id, "afl")) {
            if (strcmp(type, "result")) return;
            char room[256] = ""; xml_attr(s, "from", room, sizeof room);
            const char *it = s;
            while ((it = strstr(it, "<item"))) {
                const char *gt = strchr(it, '>'); if (!gt) break;
                char item[400]; size_t L = (size_t)(gt - it) + 1; if (L >= sizeof item) L = sizeof item - 1;
                memcpy(item, it, L); item[L] = '\0';
                char jid[256] = "", aff[32] = "";
                xml_attr(item, "jid", jid, sizeof jid); xml_attr(item, "affiliation", aff, sizeof aff);
                if (jid[0]) { char m[360]; snprintf(m, sizeof m, "  %s - %s", aff[0] ? aff : "?", jid); emit(a, TRI_EV_STATUS, room, m); }
                it = gt + 1;
            }
            return;
        }
        if (!strncmp(id, "di", 2) && !strcmp(type, "result")) {
            const char *ns = strstr(s, "urn:xmpp:http:upload:0") ? "urn:xmpp:http:upload:0"
                           : strstr(s, "eu:siacs:conversations:http:upload") ? "eu:siacs:conversations:http:upload" : NULL;
            if (ns && !p->upload_service[0]) {
                char from[256] = "";
                if (!xml_attr(s, "from", from, sizeof from) || !from[0]) snprintf(from, sizeof from, "%s", p->domain);
                snprintf(p->upload_service, sizeof p->upload_service, "%s", from);
                snprintf(p->upload_ns, sizeof p->upload_ns, "%s", ns);
                char m[320]; snprintf(m, sizeof m, "file upload available (%s)", from);
                emit(a, TRI_EV_STATUS, NULL, m);
            }
            return;
        }
        if (!strncmp(id, "up", 2)) {
            xup_t *ctx = NULL; int idx = -1;
            for (int i = 0; i < p->npend; i++) if (!strcmp(p->pend[i]->id, id)) { ctx = p->pend[i]; idx = i; break; }
            if (!ctx) return;
            p->pend[idx] = p->pend[--p->npend];
            if (strcmp(type, "result") != 0) { up_emit(a, ctx, TRI_EV_ERROR, "upload slot request was rejected"); free(ctx->data); free(ctx); return; }
            char puturl[1024] = "", geturl[1024] = "";
            const char *put = strstr(s, "<put"), *get = strstr(s, "<get");
            if (put) xml_attr(put, "url", puturl, sizeof puturl);
            if (get) xml_attr(get, "url", geturl, sizeof geturl);
            xml_unescape(puturl); xml_unescape(geturl);
            if (!puturl[0] || !geturl[0]) { up_emit(a, ctx, TRI_EV_ERROR, "upload slot missing a URL"); free(ctx->data); free(ctx); return; }
            snprintf(ctx->geturl, sizeof ctx->geturl, "%s", geturl);

            const char *hdrs[6]; char hbuf[6][512]; int nh = 0;
            if (put) { const char *pe = strstr(put, "</put>"), *h = put;
                while (nh < 6 && (h = strstr(h, "<header"))) {
                    if (pe && h > pe) break;
                    char name[64], val[400];
                    if (xml_attr(h, "name", name, sizeof name) && xml_text(h, "header", val, sizeof val)) {
                        snprintf(hbuf[nh], sizeof hbuf[nh], "%s: %s", name, val); hdrs[nh] = hbuf[nh]; nh++;
                    }
                    const char *gt2 = strchr(h, '>'); h = gt2 ? gt2 + 1 : h + 7;
                }
            }
            if (tri_http_put(tri_account_core(a), puturl, ctx->ctype, ctx->data, ctx->len, hdrs, nh, xmpp_put_done, ctx) != 0) {
                up_emit(a, ctx, TRI_EV_ERROR, tri_last_error()); free(ctx->data); free(ctx); return;
            }
            free(ctx->data); ctx->data = NULL; ctx->len = 0;
            return;
        }
        if (!strcmp(id, "mod1") && !strcmp(type, "error")) {
            char txt[256] = "";
            if (!xml_text(s, "text", txt, sizeof txt) || !txt[0]) snprintf(txt, sizeof txt, "moderation action was refused by the server");
            emit(a, TRI_EV_ERROR, NULL, txt);
            return;
        }
        if (!strcmp(id, "vc1")) {
            char from[256] = ""; xml_attr(s, "from", from, sizeof from);
            char bare[256]; bare_jid(from[0] ? from : "profile", bare, sizeof bare);
            if (strcmp(type, "result")) { emit(a, TRI_EV_STATUS, bare, "no profile available"); return; }
            char fn[256] = "", nick[256] = "", email[256] = "";
            xml_text(s, "FN", fn, sizeof fn); xml_text(s, "NICKNAME", nick, sizeof nick); xml_text(s, "USERID", email, sizeof email);
            char m[900]; int k = snprintf(m, sizeof m, "profile %s", bare);
            if (fn[0])    k += snprintf(m + k, sizeof m - k, " - name: %s", fn);
            if (nick[0])  k += snprintf(m + k, sizeof m - k, ", nick: %s", nick);
            if (email[0]) k += snprintf(m + k, sizeof m - k, ", email: %s", email);
            if (!fn[0] && !nick[0] && !email[0]) snprintf(m + k, sizeof m - k, " - (empty vCard)");
            emit(a, TRI_EV_STATUS, bare, m);
            return;
        }
        if (strstr(s, "<ping xmlns='urn:xmpp:ping'")) {
            char from[256]; if (xml_attr(s, "from", from, sizeof from)) xs_sendf(a, "<iq type='result' to='%s' id='%s'/>", from, id);
        }

        if (!strcmp(type, "get") && strstr(s, "<query xmlns='http://jabber.org/protocol/disco#info'")) {
            char from[256] = ""; xml_attr(s, "from", from, sizeof from);
            char node[160] = ""; const char *qq = strstr(s, "<query"); if (qq) xml_attr(qq, "node", node, sizeof node);
            if (from[0]) send_disco_info(a, from, id, node);
        }
        return;
    }
    if (!strncmp(s, "<message", 8)) {
        if (strstr(s, "urn:xmpp:mam:2")) { handle_mam_result(a, s); return; }
        if (strstr(s, "urn:xmpp:carbons:2")) { handle_carbon(a, s); return; }
        if (strstr(s, "urn:xmpp:jingle-message:0")) { handle_jmi(a, s); return; }
        char from[256] = "", type[16] = "", body[1500] = "";
        xml_attr(s, "from", from, sizeof from);
        xml_attr(s, "type", type, sizeof type);
        char bare[256]; bare_jid(from, bare, sizeof bare);
        char target[256]; snprintf(target, sizeof target, "%s", bare);
        const char *nick;
        int self_echo = 0;
        if (!strcmp(type, "groupchat")) {
            nick = strchr(from, '/'); nick = nick ? nick + 1 : from;

            self_echo = (!strcmp(nick, p->node) && !strstr(s, "urn:xmpp:delay"));
        } else {
            int is_muc = 0;
            for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], bare)) { is_muc = 1; break; }
            if (is_muc && strchr(from, '/')) { snprintf(target, sizeof target, "%s", from); nick = strchr(from, '/') + 1; }
            else nick = target;
        }

        if (!self_echo && strcmp(type, "groupchat") && strstr(s, "urn:xmpp:receipts") && strstr(s, "<request")) {
            char mid[128]; if (xml_attr(s, "id", mid, sizeof mid) && mid[0]) {
                char fesc[300], iesc[160]; xml_escape(from, fesc, sizeof fesc); xml_escape(mid, iesc, sizeof iesc);
                xs_sendf(a, "<message to='%s'><received xmlns='urn:xmpp:receipts' id='%s'/></message>", fesc, iesc);
            }
        }

        if (!self_echo && strstr(s, "http://jabber.org/protocol/chatstates")) {
            const char *cs = strstr(s, "<composing") ? "composing"
                           : strstr(s, "<paused")    ? "paused"
                           : strstr(s, "<inactive")  ? "inactive"
                           : strstr(s, "<gone")      ? "gone"
                           : strstr(s, "<active")    ? "active" : NULL;
            if (cs) { tri_event_t tv = { TRI_EV_TYPING, tri_account_key(a), target, cs, nick, 0 };
                      tri_emit(tri_account_core(a), &tv); }
        }

        if (!self_echo && p->omemo) {
            const char *enc = strstr(s, "<encrypted");
            if (enc && strstr(s, OMEMO_NS)) {
                tri_core *c = tri_account_core(a);
                uint8_t pt[2048];
                int pl = omemo_store_decrypt(p->omemo, bare, enc, pt, sizeof pt - 1);
                if (pl > 0) {
                    pt[pl] = '\0';
                    tri_log(c, "omemo: decrypted %d-byte message from %s", pl, bare);
                    tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), target, (const char *)pt, nick, 0, 1 };
                    tri_emit(tri_account_core(a), &ev);
                } else if (pl == 0) {
                    tri_log(c, "omemo: message from %s not addressed to our device %u (skipped)", bare, omemo_store_device_id(p->omemo));
                } else {
                    tri_log(c, "omemo: DECRYPT FAILED for message from %s (session/key/wire mismatch)", bare);
                    emit(a, TRI_EV_ERROR, target, "OMEMO: could not decrypt a message (see debug console)");
                }
                return;
            }
        }

        if (!self_echo && strstr(s, "urn:xmpp:reactions:0")) {
            char emos[256] = ""; size_t eo = 0;
            for (const char *h = strstr(s, "<reactions"); h && (h = strstr(h, "<reaction")); ) {
                const char *gt = strchr(h, '>'); if (!gt) break;
                if (gt[-1] != '/' && gt[1] != '<') {
                    const char *e = strstr(gt + 1, "</reaction>");
                    if (e && e > gt + 1) {
                        if (eo && eo + 1 < sizeof emos) emos[eo++] = ' ';
                        size_t L = (size_t)(e - (gt + 1)); if (L > sizeof emos - eo - 1) L = sizeof emos - eo - 1;
                        memcpy(emos + eo, gt + 1, L); eo += L; emos[eo] = '\0';
                    }
                }
                h = gt + 1;
            }
            char m[400]; snprintf(m, sizeof m, "%s reacted %s", nick, emos[0] ? emos : "(cleared)");
            emit(a, TRI_EV_STATUS, target, m);
            return;
        }
        if (!xml_text(s, "body", body, sizeof body) || !body[0]) return;
        if (self_echo) return;

        if (strstr(s, "urn:xmpp:reply:0")) {
            size_t bo = 0;

            const char *fb = NULL;
            for (const char *h = s; (h = strstr(h, "<fallback")); h += 9) {
                char fr[48];
                if (xml_attr(h, "for", fr, sizeof fr) && !strcmp(fr, "urn:xmpp:reply:0")) { fb = h; break; }
            }
            const char *bm = fb ? strstr(fb, "<body") : NULL;
            char es[16] = "";
            if (bm && xml_attr(bm, "end", es, sizeof es) && es[0]) {
                long want = atol(es), cp = 0;
                while (body[bo] && cp < want) { unsigned char ch = (unsigned char)body[bo];
                    bo += ch < 0x80 ? 1 : ch < 0xE0 ? 2 : ch < 0xF0 ? 3 : 4; cp++; }
            } else if (body[0] == '>') {
                for (const char *nl; body[bo] == '>' && (nl = strchr(body + bo, '\n')); )
                    bo = (size_t)(nl - body) + 1;
            }
            while (body[bo] == ' ' || body[bo] == '\t') bo++;

            if (bo > 0 && body[bo] && body[bo] != '\n' && body[bo - 1] != '\n') {
                size_t len = strlen(body);
                if (len + 1 < sizeof body) { memmove(body + bo + 1, body + bo, len - bo + 1); body[bo] = '\n'; }
            }
        }

        if (strstr(s, "urn:xmpp:message-correct:0") && strlen(body) + 11 < sizeof body)
            strcat(body, "  (edited)");

        long long ets = 0; int ehist = 0;
        if (!strcmp(type, "groupchat")) {
            const char *dl = strstr(s, "<delay");
            if (dl && strstr(s, "urn:xmpp:delay")) {
                char stamp[40]; if (xml_attr(dl, "stamp", stamp, sizeof stamp)) ets = iso8601_epoch(stamp);
                ehist = 1;
            }
        }
        char msgid[128] = ""; xml_attr(s, "id", msgid, sizeof msgid);
        tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), target, body, nick, ets, 0, ehist, msgid[0] ? msgid : NULL };
        tri_emit(tri_account_core(a), &ev);
        return;
    }
    if (!strncmp(s, "<presence", 9)) {
        char from[256] = "", type[16] = "";
        xml_attr(s, "from", from, sizeof from);
        xml_attr(s, "type", type, sizeof type);
        char target[256]; bare_jid(from, target, sizeof target);

        int is_room = 0;
        for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], target)) { is_room = 1; break; }
        const char *res = strchr(from, '/');
        if (is_room && res && res[1]) {
            if (!strcmp(type, "unavailable")) tri_roster_remove_from(a, target, res + 1);
            else                              tri_roster_upsert(a, target, res + 1, 0);
            muji_track(a, target, res + 1, s, type);
            return;
        }
        char line[400]; snprintf(line, sizeof line, "%s is %s", from, type[0] ? type : "available");
        emit(a, TRI_EV_STATUS, target, line);
        return;
    }
}

static long stanza_end(const char *b, size_t len) {
    size_t i = 0; int depth = 0;
    while (i < len) {
        if (b[i] == '<') {
            size_t j = i + 1; char q = 0; int closing = (j < len && b[j] == '/');
            while (j < len) { char c = b[j]; if (q) { if (c == q) q = 0; } else { if (c == '"' || c == '\'') q = c; else if (c == '>') break; } j++; }
            if (j >= len) return -1;
            int selfclose = (b[j - 1] == '/');
            if (closing) depth--; else if (!selfclose) depth++;
            i = j + 1;
            if (depth <= 0) return (long)i;
        } else i++;
    }
    return -1;
}

static void xmpp_consume(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    for (;;) {
        size_t i = 0;
        while (i < p->rlen && isspace((unsigned char)p->rbuf[i])) i++;
        if (i) { memmove(p->rbuf, p->rbuf + i, p->rlen - i); p->rlen -= i; }
        if (p->rlen == 0) return;
        if (p->rbuf[0] != '<') { p->rlen = 0; return; }
        p->rbuf[p->rlen < sizeof p->rbuf ? p->rlen : sizeof p->rbuf - 1] = '\0';

        size_t consume = 0;
        if (p->rlen >= 2 && p->rbuf[1] == '?') {
            char *e = strstr(p->rbuf, "?>"); if (!e) return; consume = (size_t)(e - p->rbuf) + 2;
        } else if (!strncmp(p->rbuf, "<stream:stream", 14)) {
            char *e = memchr(p->rbuf, '>', p->rlen); if (!e) return; consume = (size_t)(e - p->rbuf) + 1;
        } else if (!strncmp(p->rbuf, "</stream:stream", 15)) {
            xmpp_teardown(a, NULL); tri_account_notify_down(a, "xmpp: stream closed by server"); return;
        } else {
            long end = stanza_end(p->rbuf, p->rlen);
            if (end < 0) return;
            char save = p->rbuf[end]; p->rbuf[end] = '\0';
            handle_stanza(a, p->rbuf);
            if (tri_account_priv(a) == NULL) return;
            p->rbuf[end] = save;
            consume = (size_t)end;
        }
        memmove(p->rbuf, p->rbuf + consume, p->rlen - consume);
        p->rlen -= consume;
    }
}

static int parse_url(xp_priv *p, const char *url) {
    char buf[600]; snprintf(buf, sizeof buf, "%s", url ? url : "");
    char *qs = strchr(buf, '?');
#ifdef TRI_MUJI_MESH

    p->mesh_mixed = 1;
    if (qs) { if (strstr(qs, "persink")) p->mesh_mixed = 0; else if (strstr(qs, "mix")) p->mesh_mixed = 1; }
#endif
    if (qs) *qs = '\0';
    char *s = buf;
    if      (!strncmp(s, "xmpp+plain://", 13)) { p->tls = 0; s += 13; }
    else if (!strncmp(s, "xmpp://", 7))        { p->tls = 1; s += 7; }
    else return tri_set_error("xmpp: config must start with xmpp:// or xmpp+plain:// (got '%s')", url);
    char *slash = strchr(s, '/');
    if (slash) { *slash++ = '\0'; snprintf(p->resource, sizeof p->resource, "%s", slash); }
    if (!p->resource[0]) snprintf(p->resource, sizeof p->resource, "trichat");
    char *at = strrchr(s, '@');
    if (!at) return tri_set_error("xmpp: config needs user@host (got '%s')", url);
    *at = '\0';
    char *colon = strchr(s, ':');
    if (colon) { *colon = '\0'; snprintf(p->pass, sizeof p->pass, "%s", colon + 1); }
    snprintf(p->node, sizeof p->node, "%s", s);
    s = at + 1;
    char *pcolon = strchr(s, ':');
    if (pcolon) { *pcolon = '\0'; snprintf(p->port, sizeof p->port, "%s", pcolon + 1); }
    else snprintf(p->port, sizeof p->port, "5222");
    snprintf(p->host, sizeof p->host, "%s", s);
    snprintf(p->domain, sizeof p->domain, "%s", s);
    if (!p->node[0]) return tri_set_error("xmpp: no username in config");
    return 0;
}

static int tls_check_pin(account_t *a, const char *host) {
    if (tri_account_insecure(a)) return 0;
    xp_priv *p = tri_account_priv(a);
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
        return tri_set_error("xmpp: TLS certificate for %s changed since first use (possible MITM) - add ?insecure to override", host);
    if (r == TRI_PIN_NEW) { tri_tls_pin_store(c, host, fp); emit(a, TRI_EV_STATUS, NULL, "pinned server TLS certificate (first use)"); }
    return 0;
}

static void tls_pump(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (wolfSSL_connect(p->ssl) == WOLFSSL_SUCCESS) {
        tri_account_set_write_interest(a, 0);
        p->secured = 1;
        if (tls_check_pin(a, p->host) != 0) { char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                                              xmpp_teardown(a, NULL); tri_account_notify_failed(a, m); return; }
        p->state = ST_STREAM1;
        emit(a, TRI_EV_STATUS, NULL, "TLS up");
        send_stream_header(a);
        return;
    }
    int err = wolfSSL_get_error(p->ssl, 0);
    if (err == WOLFSSL_ERROR_WANT_WRITE) { tri_account_set_write_interest(a, 1); return; }
    if (err == WOLFSSL_ERROR_WANT_READ)  { tri_account_set_write_interest(a, 0); return; }
    char e[80]; wolfSSL_ERR_error_string(err, e);
    tri_set_error("xmpp: TLS handshake with %s failed: %s", p->host, e);
    char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
    xmpp_teardown(a, NULL);
    tri_account_notify_down(a, m);
}

static void xmpp_resolved(void *ud, int ok, const struct sockaddr *sa, socklen_t salen,
                          int socktype, int proto, const char *err) {
    account_t *a = ud;
    xp_priv *p = tri_account_priv(a);
    if (!p) return;
    p->resolve = NULL;
    if (!ok) {
        tri_set_error("xmpp: cannot resolve %s:%s: %s", p->host, p->port, err);
        char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
        xmpp_teardown(a, NULL); tri_account_notify_down(a, m); return;
    }
    int fd = socket(sa->sa_family, socktype, proto);
    if (fd < 0) { tri_set_error("xmpp: socket() failed: %s", strerror(errno));
                  char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                  xmpp_teardown(a, NULL); tri_account_notify_down(a, m); return; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int rc = connect(fd, sa, salen);
    if (rc != 0 && errno != EINPROGRESS) {
        tri_set_error("xmpp: connect to %s:%s failed: %s", p->host, p->port, strerror(errno));
        char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
        close(fd); xmpp_teardown(a, NULL); tri_account_notify_down(a, m); return;
    }
    tri_account_set_fd(a, fd);
    p->state = ST_CONNECTING;
    tri_account_set_write_interest(a, 1);
    emit(a, TRI_EV_STATUS, NULL, "connecting...");
}

static int xmpp_connect(account_t *a) {
    xp_priv *p = calloc(1, sizeof *p);
    if (!p) return tri_set_error("xmpp: out of memory");
    p->vid_fd = p->vid_in_fd = -1;
    if (parse_url(p, tri_account_config(a)) != 0) { free(p); return -1; }
    tri_account_set_priv(a, p);
    p->state = ST_RESOLVING;
    p->resolve = tri_resolve_start(tri_account_core(a), p->host, p->port, SOCK_STREAM, xmpp_resolved, a);
    if (!p->resolve) { free(p); tri_account_set_priv(a, NULL); return -1; }
    emit(a, TRI_EV_STATUS, NULL, "resolving...");
    return 0;
}

static void xmpp_teardown(account_t *a, const char *why) {
    xp_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->resolve) { tri_resolve_cancel(p->resolve); p->resolve = NULL; }
    int fd = tri_account_fd(a);
    if (fd >= 0) {
        if (p->secured) xs_send(a, "</stream:stream>");
        if (p->ssl) { if (p->secured) wolfSSL_shutdown(p->ssl); wolfSSL_free(p->ssl); }
        if (p->ctx) wolfSSL_CTX_free(p->ctx);
        close(fd);
    }
    tri_account_set_write_interest(a, 0);
    if (p->omemo) { omemo_store_close(p->omemo); p->omemo = NULL; }
    tri_roster_clear_account(a);
    for (int i = 0; i < p->npend; i++) { free(p->pend[i]->data); free(p->pend[i]); }
    call_end_ice(a);
#ifdef TRI_MUJI_MESH
    mesh_teardown_all(a);
#endif
    if (why) emit(a, TRI_EV_STATUS, NULL, why);
    free(p);
    tri_account_set_priv(a, NULL);
    tri_account_set_fd(a, -1);
}

static void xmpp_disconnect(account_t *a) { xmpp_teardown(a, tri_account_priv(a) ? "disconnected" : NULL); }

static void xmpp_on_readable(account_t *a, int fd) {
    xp_priv *p = tri_account_priv(a);
    if (!p) return; (void)fd;
    if (p->state == ST_TLS_HS) { tls_pump(a); return; }
    for (;;) {
        ssize_t r;
        if (p->secured) r = wolfSSL_read(p->ssl, p->rbuf + p->rlen, sizeof p->rbuf - p->rlen - 1);
        else            r = read(fd, p->rbuf + p->rlen, sizeof p->rbuf - p->rlen - 1);
        if (r <= 0) {
            int wb;
            if (p->secured) { int e = wolfSSL_get_error(p->ssl, r); wb = (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE); }
            else wb = (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
            if (wb) return;
            xmpp_teardown(a, NULL);
            tri_account_notify_down(a, r == 0 ? "connection closed by server" : "connection error");
            return;
        }
        p->rlen += r;
        xmpp_consume(a);
        if (tri_account_priv(a) == NULL) return;
        if (p->rlen >= sizeof p->rbuf - 1) { xmpp_teardown(a, NULL); tri_account_notify_down(a, "xmpp: stanza too large"); return; }
    }
}

static void xmpp_on_writable(account_t *a, int fd) {
    xp_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->state == ST_CONNECTING) {
        int err = 0; socklen_t l = sizeof err; getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) { tri_set_error("xmpp: connect to %s:%s failed: %s", p->host, p->port, strerror(err));
                   char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                   xmpp_teardown(a, NULL); tri_account_notify_down(a, m); return; }
        tri_account_set_write_interest(a, 0);
        p->state = ST_STREAM0;
        send_stream_header(a);
        return;
    }
    if (p->state == ST_TLS_HS) tls_pump(a);
}

static int is_groupchat_target(xp_priv *p, const char *target) {
    for (int i = 0; i < p->nrooms; i++) if (!strcmp(p->rooms[i], target)) return 1;
    return 0;
}

static void remember_sent(xp_priv *p, const char *target, const char *id) {
    for (int i = 0; i < p->nlastsent; i++)
        if (!strcmp(p->lastsent[i].target, target)) { snprintf(p->lastsent[i].id, sizeof p->lastsent[i].id, "%s", id); return; }
    int k = p->nlastsent < 16 ? p->nlastsent++ : (p->nlastsent = 16, 0);
    snprintf(p->lastsent[k].target, sizeof p->lastsent[k].target, "%s", target);
    snprintf(p->lastsent[k].id, sizeof p->lastsent[k].id, "%s", id);
}
static const char *last_sent_id(xp_priv *p, const char *target) {
    for (int i = 0; i < p->nlastsent; i++) if (!strcmp(p->lastsent[i].target, target)) return p->lastsent[i].id;
    return NULL;
}
static int xmpp_send(account_t *a, const char *target, const char *body) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("xmpp: not connected yet");
    int groupchat = is_groupchat_target(p, target);

    if (!groupchat && p->omemo && tri_channel_encrypt(a, target)) {
        uint32_t devs[8];
        int nd = omemo_store_peer_devices(p->omemo, target, devs, 8);
        if (nd > 0) {
            char enc[8192];
            if (omemo_store_encrypt(p->omemo, target, devs, NULL, nd, (const uint8_t *)body, strlen(body), enc, sizeof enc) == 0)
                return omemo_send_stanza(a, target, enc);

        } else if (omemo_begin_send(a, target, body) == 0) {
            return 0;
        }
    }
    char esc[1600]; xml_escape(body, esc, sizeof esc);
    static unsigned mc = 0; char id[24]; snprintf(id, sizeof id, "m%u", ++mc);
    remember_sent(p, target, id);

    return xs_sendf(a, "<message id='%s' to='%s' type='%s'><body>%s</body>"
                       "<active xmlns='http://jabber.org/protocol/chatstates'/>%s</message>",
                    id, target, groupchat ? "groupchat" : "chat", esc,
                    groupchat ? "" : "<request xmlns='urn:xmpp:receipts'/>");
}

static int xmpp_react(account_t *a, const char *target, const char *id, const char *emoji) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("xmpp: not connected");
    char tesc[300], iesc[64]; xml_escape(target, tesc, sizeof tesc); xml_escape(id, iesc, sizeof iesc);
    char reac[128] = "";
    if (emoji && emoji[0]) { char eesc[80]; xml_escape(emoji, eesc, sizeof eesc); snprintf(reac, sizeof reac, "<reaction>%s</reaction>", eesc); }
    return xs_sendf(a, "<message to='%s' type='%s'><reactions id='%s' xmlns='urn:xmpp:reactions:0'>%s</reactions>"
                       "<store xmlns='urn:xmpp:hints'/></message>",
                    tesc, is_groupchat_target(p, target) ? "groupchat" : "chat", iesc, reac);
}

static int xmpp_correct(account_t *a, const char *target, const char *newbody) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("xmpp: not connected");
    const char *old = last_sent_id(p, target);
    if (!old) return tri_set_error("xmpp: no message to correct in this conversation yet");
    char esc[1600], tesc[300], oesc[64]; xml_escape(newbody, esc, sizeof esc); xml_escape(target, tesc, sizeof tesc); xml_escape(old, oesc, sizeof oesc);
    static unsigned cc = 0; char id[24]; snprintf(id, sizeof id, "c%u", ++cc);
    int rc = xs_sendf(a, "<message id='%s' to='%s' type='%s'><body>%s</body>"
                         "<replace id='%s' xmlns='urn:xmpp:message-correct:0'/></message>",
                      id, tesc, is_groupchat_target(p, target) ? "groupchat" : "chat", esc, oesc);
    if (rc == 0) remember_sent(p, target, id);
    return rc;
}

static void xmpp_typing(account_t *a, const char *target, int composing) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE || !target || !target[0]) return;
    char esc[300]; xml_escape(target, esc, sizeof esc);
    xs_sendf(a, "<message to='%s' type='%s'><%s xmlns='http://jabber.org/protocol/chatstates'/></message>",
             esc, is_groupchat_target(p, target) ? "groupchat" : "chat", composing ? "composing" : "paused");
}

#define DEFAULT_STUN_HOST "stun.l.google.com"
#define DEFAULT_STUN_PORT "19302"

static int resolve_ipv4(const char *host, const char *port, char *ip, size_t ipsz) {
    struct addrinfo hints, *res = NULL; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ip, (socklen_t)ipsz);
    freeaddrinfo(res);
    return 0;
}
static int resolve_stun(char *ip, size_t ipsz, int *port) {
    if (resolve_ipv4(DEFAULT_STUN_HOST, DEFAULT_STUN_PORT, ip, ipsz) != 0) return -1;
    *port = atoi(DEFAULT_STUN_PORT);
    return 0;
}

static void dtls_send_via_ice(void *ud, const uint8_t *data, int len) {
    account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (p->ice) ice_send(p->ice, data, len);
}
static void call_media_init(account_t *a);
static void call_mic_start(account_t *a);
static void call_mic_stop(account_t *a);
static void call_video_start(account_t *a, int src);
static void call_video_stop(account_t *a);
static void xmpp_send_audio(account_t *a, const int16_t *pcm, int samples);
static void call_dtls_progress(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->dtls) return;
    if (dtls_srtp_done(p->dtls) && !p->dtls_secured) {
        p->dtls_secured = 1;
        call_media_init(a);
        char pb[256]; bare_jid(p->call.peer, pb, sizeof pb);
        char m[300]; snprintf(m, sizeof m, "[call] encrypted (DTLS-SRTP) with %s - audio flowing", pb);
        emit(a, TRI_EV_STATUS, pb, m);
    } else if (dtls_srtp_failed(p->dtls) && p->dtls_started && !p->dtls_secured) {
        char pb[256]; bare_jid(p->call.peer, pb, sizeof pb);
        char m[360]; snprintf(m, sizeof m, "[call] DTLS handshake with %s failed: %s", pb, dtls_srtp_error(p->dtls));
        emit(a, TRI_EV_ERROR, pb, m);
        p->dtls_secured = -1;
    }
}

static void call_media_init(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (p->media_ready || !p->dtls) return;
    uint8_t km[128]; int kl = dtls_srtp_keys(p->dtls, km, sizeof km);
    if (kl < 60) return;
    const uint8_t *ck = km, *sk = km + 16, *cs = km + 32, *ss = km + 46;
    int we_client = !strcmp(p->call.setup, "active");
    const uint8_t *txk = we_client ? ck : sk, *txs = we_client ? cs : ss;
    const uint8_t *rxk = we_client ? sk : ck, *rxs = we_client ? ss : cs;
    if (srtp_init(&p->srtp_tx, txk, txs) != 0 || srtp_init(&p->srtp_rx, rxk, rxs) != 0) return;
    if (p->call.has_video) srtp_init(&p->srtp_rx_v, rxk, rxs);
    int err = 0;
    p->odec = opus_decoder_create(48000, 1, &err);
    p->oenc = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &err);
    if (p->oenc) opus_encoder_ctl(p->oenc, OPUS_SET_BITRATE(24000));
    p->play = tri_audio_open(tri_account_core(a));
    p->rtp_ssrc = p->call.ssrc ? p->call.ssrc : (uint32_t)rand();
    p->rtp_pt = (p->call.npt > 0 && p->call.pts[0].id > 0) ? p->call.pts[0].id : 111;
    p->media_ready = 1;
    { char pb[256]; bare_jid(p->call.peer, pb, sizeof pb); call_signal(a, "active", pb, p->call.has_video); }
    tri_log(tri_account_core(a), "media keyed: srtp-profile=%s dtls-role=%s rtp_pt=%d ssrc=%u",
            dtls_srtp_profile(p->dtls), we_client ? "client" : "server", p->rtp_pt, p->rtp_ssrc);
    call_mic_start(a);
    if (p->call.has_video && p->want_video) call_video_start(a, p->want_video);
}

static void xmpp_send_audio(account_t *a, const int16_t *pcm, int samples) {
    xp_priv *p = tri_account_priv(a);
    if (!p->media_ready || !p->oenc) return;
    uint8_t opus[1000];
    int n = opus_encode(p->oenc, pcm, samples, opus, sizeof opus);
    if (n <= 0) return;
    uint8_t rtp[SRTP_MAX_PACKET], prot[SRTP_MAX_PACKET];
    rtp[0] = 0x80; rtp[1] = (uint8_t)p->rtp_pt;
    rtp[2] = (uint8_t)(p->rtp_seq >> 8); rtp[3] = (uint8_t)p->rtp_seq; p->rtp_seq++;
    rtp[4] = (uint8_t)(p->rtp_ts >> 24); rtp[5] = (uint8_t)(p->rtp_ts >> 16);
    rtp[6] = (uint8_t)(p->rtp_ts >> 8);  rtp[7] = (uint8_t)p->rtp_ts; p->rtp_ts += (uint32_t)samples;
    rtp[8] = (uint8_t)(p->rtp_ssrc >> 24); rtp[9] = (uint8_t)(p->rtp_ssrc >> 16);
    rtp[10] = (uint8_t)(p->rtp_ssrc >> 8); rtp[11] = (uint8_t)p->rtp_ssrc;
    memcpy(rtp + 12, opus, (size_t)n);
    int pl = srtp_protect(&p->srtp_tx, rtp, 12 + n, prot);
    if (pl > 0 && p->ice) ice_send(p->ice, prot, pl);
}

static void call_mic_stop(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->mic) return;
    tri_core_remove_fd(tri_account_core(a), tri_audio_source_fd(p->mic));
    tri_audio_capture_close(p->mic); p->mic = NULL; p->mic_n = 0;
}
static void mic_readable_cb(void *ud, int fd) {
    (void)fd; account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (!p || !p->mic) return;
    for (;;) {
        int got = tri_audio_source_read(p->mic, p->mic_acc + p->mic_n, 960 - p->mic_n);
        if (got < 0) { call_mic_stop(a); return; }
        if (got == 0) break;
        p->mic_n += got;
        if (p->mic_n >= 960) {
            if (!p->sb_playing) xmpp_send_audio(a, p->mic_acc, 960);
#ifdef TRI_MUJI_MESH
            if (!p->sb_playing) mesh_fanout_audio(a, p->mic_acc, 960);
#endif
            p->mic_n = 0;
        }
    }
}
static void call_mic_start(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (p->mic) return;
    p->mic = tri_audio_capture_open(tri_account_core(a), "");
    if (!p->mic) { emit(a, TRI_EV_STATUS, p->call.peer, "[call] mic unavailable - sending silence"); return; }
    p->mic_n = 0;
    tri_core_add_fd(tri_account_core(a), tri_audio_source_fd(p->mic), mic_readable_cb, a);
}

static int ffmpeg_has_encoder(const char *name) {
    static struct { char name[16]; int have; } cache[8];
    static int ncache;
    for (int i = 0; i < ncache; i++)
        if (!strcmp(cache[i].name, name)) return cache[i].have;
    char cmd[128]; snprintf(cmd, sizeof cmd, "ffmpeg -hide_banner -encoders 2>/dev/null | grep -qw %s", name);
    int have = system(cmd) == 0;
    if (ncache < (int)(sizeof cache / sizeof cache[0]) && strlen(name) < sizeof cache[0].name) {
        snprintf(cache[ncache].name, sizeof cache[ncache].name, "%s", name);
        cache[ncache].have = have; ncache++;
    }
    return have;
}

static const char *pick_video_codec(void) {
    if (ffmpeg_has_encoder("libvpx"))  return "VP8";
    if (ffmpeg_has_encoder("libx264")) return "H264";
    return "";
}

static int can_encode_codec(const char *name) {
    if (!strcasecmp(name, "VP8"))  return ffmpeg_has_encoder("libvpx");
    if (!strcasecmp(name, "H264")) return ffmpeg_has_encoder("libx264");
    return 0;
}

static void le16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *b, uint32_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24); }

static int spawn_pipe2(const char *cmd, int *in_fd, int *out_fd) {
    int ip[2], op[2];
    if (pipe(ip) != 0) return -1;
    if (pipe(op) != 0) { close(ip[0]); close(ip[1]); return -1; }
    pid_t pid = fork();
    if (pid < 0) { close(ip[0]); close(ip[1]); close(op[0]); close(op[1]); return -1; }
    if (pid == 0) {
        dup2(ip[0], 0); dup2(op[1], 1);
        close(ip[0]); close(ip[1]); close(op[0]); close(op[1]);

        int maxfd = (int)sysconf(_SC_OPEN_MAX); if (maxfd < 0 || maxfd > 4096) maxfd = 4096;
        for (int fd = 3; fd < maxfd; fd++) close(fd);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(ip[0]); close(op[1]);
    *in_fd = ip[1]; *out_fd = op[0];
    return (int)pid;
}

static void vdec_readable_cb(void *ud, int fd);

static void vsink_close(vsink *s, tri_core *core) {
    if (!s->started && s->pid <= 0) { free(s->pend); free(s->frame); memset(s, 0, sizeof *s); s->in_fd = s->out_fd = -1; return; }
    if (s->out_fd > 0) { tri_core_remove_fd(core, s->out_fd); close(s->out_fd); }
    if (s->in_fd > 0) close(s->in_fd);

    if (s->pid > 0) { kill((pid_t)s->pid, SIGKILL); waitpid((pid_t)s->pid, NULL, 0); }
    free(s->pend); free(s->frame);
    if (s->errlog[0]) unlink(s->errlog);
    memset(s, 0, sizeof *s);
    s->in_fd = s->out_fd = -1;
}

#define VSINK_MAX_RESPAWN 6
static void vsink_fail(vsink *s, tri_core *core) {
    int r = s->respawns;
    vsink_close(s, core);
    if (r >= VSINK_MAX_RESPAWN) { s->failed = 1; return; }
    s->respawns = r + 1;
}

static void vsink_flush(vsink *s, tri_core *core) {
    if (s->in_fd < 0) return;
    while (s->pend_off < s->pend_len) {
        ssize_t w = write(s->in_fd, s->pend + s->pend_off, (size_t)(s->pend_len - s->pend_off));
        if (w > 0) { s->pend_off += (int)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        vsink_fail(s, core); return;
    }
    s->pend_off = s->pend_len = 0;
}

static void vsink_wr(vsink *s, tri_core *core, const uint8_t *b, int n) {
    if (s->in_fd < 0 || n <= 0) return;
    if (s->pend_off) { memmove(s->pend, s->pend + s->pend_off, (size_t)(s->pend_len - s->pend_off)); s->pend_len -= s->pend_off; s->pend_off = 0; }
    if (s->pend_len + n > VSINK_PEND_CAP) { vsink_fail(s, core); return; }
    memcpy(s->pend + s->pend_len, b, (size_t)n); s->pend_len += n;
    vsink_flush(s, core);
}
static int vsink_spawn(vsink *s, account_t *a, int which, int is_h264) {
    if (s->started || s->failed) return s->started;
    tri_core *core = tri_account_core(a);
    s->pend = malloc(VSINK_PEND_CAP);
    s->frame = malloc(VDEC_FRAME);
    if (!s->pend || !s->frame) { free(s->pend); free(s->frame); s->pend = s->frame = NULL; s->failed = 1; return 0; }
    s->pend_len = s->pend_off = s->frame_len = 0; s->is_h264 = is_h264; s->which = which;
    snprintf(s->errlog, sizeof s->errlog, "/tmp/trichat-vdec-%d-%d.log", (int)getpid(), which);

    char cmd[512];
    snprintf(cmd, sizeof cmd,
             "exec ffmpeg -hide_banner -loglevel error -fflags nobuffer -flags low_delay -probesize 32 -analyzeduration 0 "
             "-f %s -i - -an -vf 'scale=%d:%d:force_original_aspect_ratio=decrease,pad=%d:%d:(ow-iw)/2:(oh-ih)/2,format=rgba' "
             "-f rawvideo -pix_fmt rgba - 2>%s",
             is_h264 ? "h264" : "ivf", VDEC_W, VDEC_H, VDEC_W, VDEC_H, s->errlog);
    signal(SIGPIPE, SIG_IGN);
    s->pid = spawn_pipe2(cmd, &s->in_fd, &s->out_fd);
    if (s->pid < 0) { free(s->pend); free(s->frame); s->pend = s->frame = NULL; s->in_fd = s->out_fd = -1; s->failed = 1;
                      tri_log(core, "video: could not spawn ffmpeg decoder"); return 0; }
    int fl;
    if ((fl = fcntl(s->in_fd, F_GETFL, 0)) >= 0)  fcntl(s->in_fd, F_SETFL, fl | O_NONBLOCK);
    if ((fl = fcntl(s->out_fd, F_GETFL, 0)) >= 0) fcntl(s->out_fd, F_SETFL, fl | O_NONBLOCK);
#ifdef F_SETPIPE_SZ

    fcntl(s->out_fd, F_SETPIPE_SZ, VDEC_PIPE);
    fcntl(s->in_fd, F_SETPIPE_SZ, 1 << 18);
#endif
    tri_core_add_fd(core, s->out_fd, vdec_readable_cb, a);
    s->started = 1;
    tri_log(core, "video: decoding %s stream for %s preview", is_h264 ? "H264" : "VP8", which == TRI_VIDEO_SELF ? "self" : "remote");
    return 1;
}

static void vsink_read(vsink *s, account_t *a) {
    if (s->out_fd < 0 || !s->frame) return;
    tri_core *core = tri_account_core(a);
    for (;;) {
        ssize_t r = read(s->out_fd, s->frame + s->frame_len, (size_t)(VDEC_FRAME - s->frame_len));
        if (r > 0) {
            s->frame_len += (int)r;
            if (s->frame_len >= VDEC_FRAME) {
                tri_call_video_publish(core, tri_account_key(a), s->which, VDEC_W, VDEC_H, s->frame);
                s->frame_len = 0;
            }
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        vsink_fail(s, core); return;
    }
}

static int vp8_dims(const uint8_t *f, int n, int *w, int *h) {
    if (n < 10 || (f[0] & 1)) return 0;
    if (f[3] != 0x9d || f[4] != 0x01 || f[5] != 0x2a) return 0;
    *w = ((f[7] << 8) | f[6]) & 0x3fff;
    *h = ((f[9] << 8) | f[8]) & 0x3fff;
    return *w > 0 && *h > 0;
}

static void vsink_vp8(vsink *s, account_t *a, int which, const uint8_t *frame, int flen) {
    if (s->failed) return;
    int w = 0, h = 0;
    int key = vp8_dims(frame, flen, &w, &h);

    if (key && s->started && (w != s->dec_w || h != s->dec_h))
        vsink_close(s, tri_account_core(a));
    if (!s->started) {
        if (!key) return;
        if (!vsink_spawn(s, a, which, 0)) return;
        s->dec_w = w; s->dec_h = h;
        uint8_t hdr[32]; memset(hdr, 0, sizeof hdr);
        memcpy(hdr, "DKIF", 4); le16(hdr + 6, 32); memcpy(hdr + 8, "VP80", 4);
        le16(hdr + 12, (uint16_t)w); le16(hdr + 14, (uint16_t)h);
        le32(hdr + 16, 30); le32(hdr + 20, 1);
        vsink_wr(s, tri_account_core(a), hdr, 32); s->ivf_hdr = 1;
    }
    uint8_t fh[12]; le32(fh, (uint32_t)flen); le32(fh + 4, s->ivf_ts); le32(fh + 8, 0); s->ivf_ts++;
    vsink_wr(s, tri_account_core(a), fh, 12); vsink_wr(s, tri_account_core(a), frame, flen);
}

static void vsink_h264(vsink *s, account_t *a, int which, const uint8_t *b, int n) {
    if (s->failed || n <= 0) return;
    if (!s->started && !vsink_spawn(s, a, which, 1)) return;
    vsink_wr(s, tri_account_core(a), b, n);
}
static void vdec_readable_cb(void *ud, int fd) {
    account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->vrx.out_fd == fd)           vsink_read(&p->vrx, a);
    else if (p->vtx_prev.out_fd == fd) vsink_read(&p->vtx_prev, a);
}

struct vdec_target { account_t *a; int which; };

static void vdec_publish(void *ud, int w, int h, const uint8_t *rgba) {
    struct vdec_target *t = ud;
    tri_call_video_publish(tri_account_core(t->a), tri_account_key(t->a), t->which, w, h, rgba);
}

static void vdec_async_readable(void *ud, int fd) {
    account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (!p) return;
    tri_core *core = tri_account_core(a);
    if (p->vrx_dec && tri_vdec_async_fd(p->vrx_dec) == fd) {
        struct vdec_target t = { a, TRI_VIDEO_REMOTE };
        tri_vdec_async_drain(p->vrx_dec, vdec_publish, &t);
        if (tri_vdec_async_fatal(p->vrx_dec)) { tri_core_remove_fd(core, fd); tri_vdec_async_free(p->vrx_dec); p->vrx_dec = NULL; p->vrx_dec_tried = 0; }
    } else if (p->vtx_dec && tri_vdec_async_fd(p->vtx_dec) == fd) {
        struct vdec_target t = { a, TRI_VIDEO_SELF };
        tri_vdec_async_drain(p->vtx_dec, vdec_publish, &t);
        if (tri_vdec_async_fatal(p->vtx_dec)) { tri_core_remove_fd(core, fd); tri_vdec_async_free(p->vtx_dec); p->vtx_dec = NULL; p->vtx_dec_tried = 0; }
    }
#ifdef TRI_MUJI_MESH
    else for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active || !mp->vdec || tri_vdec_async_fd(mp->vdec) != fd) continue;
        struct vdec_target t = { a, mp->vwhich };
        tri_vdec_async_drain(mp->vdec, vdec_publish, &t);
        if (tri_vdec_async_fatal(mp->vdec)) { tri_core_remove_fd(core, fd); tri_vdec_async_free(mp->vdec); mp->vdec = NULL; mp->vdec_tried = 0; }
        break;
    }
#endif
}

static int vdec_try(account_t *a, tri_vdec_async **dec, int *tried, int which, const char *codec,
                    const uint8_t *data, int len) {
    (void)which;
    if (!*tried) {
        *dec = tri_vdec_async_new(codec); *tried = 1;
        if (*dec) tri_core_add_fd(tri_account_core(a), tri_vdec_async_fd(*dec), vdec_async_readable, a);
    }
    if (!*dec) return 0;
    if (tri_vdec_async_feed(*dec, data, len) < 0) {
        tri_core_remove_fd(tri_account_core(a), tri_vdec_async_fd(*dec));
        tri_vdec_async_free(*dec); *dec = NULL; *tried = 0;
    }
    return 1;
}
static void call_video_stop(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    vsink_close(&p->vtx_prev, tri_account_core(a)); p->vtx_prev_on = 0;
    if (p->vtx_dec) { tri_core_remove_fd(tri_account_core(a), tri_vdec_async_fd(p->vtx_dec));
                      tri_vdec_async_free(p->vtx_dec); p->vtx_dec = NULL; } p->vtx_dec_tried = 0;
    free(p->vtx_nalbuf); p->vtx_nalbuf = NULL; p->vtx_nalcap = 0;
    tri_call_video_clear(tri_account_core(a), tri_account_key(a), TRI_VIDEO_SELF);
    if (!p->vid_pipe && !p->vid_sending && p->vid_pid <= 0) return;
    if (p->vid_fd >= 0) tri_core_remove_fd(tri_account_core(a), p->vid_fd);
    if (p->vid_pipe) pclose(p->vid_pipe);

    if (p->vid_in_fd >= 0) { close(p->vid_in_fd); p->vid_in_fd = -1; }
    if (p->vid_pid > 0 && p->vid_fd >= 0) { close(p->vid_fd); p->vid_fd = -1; }
    if (p->vid_pid > 0) { kill((pid_t)p->vid_pid, SIGKILL); waitpid((pid_t)p->vid_pid, NULL, 0); p->vid_pid = 0; }
#ifdef TRI_X11
    if (p->x11) { x11cap_close(p->x11); p->x11 = NULL; }
#endif
    free(p->vid_raw); p->vid_raw = NULL; p->vid_raw_cap = p->vid_raw_len = p->vid_raw_off = 0;
    free(p->vid_selfprev); p->vid_selfprev = NULL;
    p->vid_pipe = NULL; p->vid_fd = -1; p->vid_sending = 0;
    free(p->vid_ivf); p->vid_ivf = NULL;
    free(p->vid_h264); p->vid_h264 = NULL;
    free(p->pace_q); p->pace_q = NULL; free(p->pace_len); p->pace_len = NULL;
    p->pace_head = p->pace_count = 0; p->pace_budget = 0;
    if (p->srtp_tx_v.ready) srtp_clear(&p->srtp_tx_v);
    if (p->vid_errlog[0]) {
        FILE *ef = fopen(p->vid_errlog, "r");
        if (ef) { char eb[400]; size_t en = fread(eb, 1, sizeof eb - 1, ef); eb[en] = '\0'; fclose(ef);
                  if (en) tri_log(tri_account_core(a), "video: ffmpeg said: %.380s", eb); }
        unlink(p->vid_errlog); p->vid_errlog[0] = '\0';
    }
}
#define PACE_SLOTS     256
#define PACE_BURST_MAX 8000.0

static void pace_enqueue(xp_priv *p, const uint8_t *pkt, int len) {
    if (!p->pace_q || len <= 0 || len > SRTP_MAX_PACKET) return;
    if (p->pace_count >= PACE_SLOTS) { p->pace_dropped++; return; }
    int tail = (p->pace_head + p->pace_count) % PACE_SLOTS;
    memcpy(p->pace_q + (size_t)tail * SRTP_MAX_PACKET, pkt, (size_t)len);
    p->pace_len[tail] = (uint16_t)len;
    p->pace_count++;
}

static void pace_drain(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    double now = now_s();
    double dt = now - p->pace_last; p->pace_last = now;
    if (!p->ice || !p->pace_q || p->pace_count == 0) { p->pace_budget = 0; return; }
    if (dt < 0) dt = 0; else if (dt > 0.25) dt = 0.25;
    p->pace_budget += p->pace_rate * dt;
    if (p->pace_budget > PACE_BURST_MAX) p->pace_budget = PACE_BURST_MAX;
    while (p->pace_count > 0 && p->pace_budget >= p->pace_len[p->pace_head]) {
        const uint8_t *slot = p->pace_q + (size_t)p->pace_head * SRTP_MAX_PACKET;
        int len = p->pace_len[p->pace_head];
        ice_send(p->ice, slot, len);
        p->pace_budget -= len;
        p->pace_head = (p->pace_head + 1) % PACE_SLOTS;
        p->pace_count--;
    }
}

static void send_video_rtp(account_t *a, const uint8_t *payload, int plen, int marker, uint32_t ts) {
    xp_priv *p = tri_account_priv(a);
    if (plen <= 0 || plen + 12 + SRTP_AUTH_TAG_LEN > SRTP_MAX_PACKET) return;
    uint8_t rtp[SRTP_MAX_PACKET], prot[SRTP_MAX_PACKET];
    rtp[0] = 0x80;
    rtp[1] = (uint8_t)(p->vid_pt | (marker ? 0x80 : 0));
    rtp[2] = (uint8_t)(p->vrtp_seq >> 8); rtp[3] = (uint8_t)p->vrtp_seq; p->vrtp_seq++;
    rtp[4] = (uint8_t)(ts >> 24); rtp[5] = (uint8_t)(ts >> 16); rtp[6] = (uint8_t)(ts >> 8); rtp[7] = (uint8_t)ts;
    rtp[8] = (uint8_t)(p->vrtp_ssrc >> 24); rtp[9] = (uint8_t)(p->vrtp_ssrc >> 16);
    rtp[10] = (uint8_t)(p->vrtp_ssrc >> 8); rtp[11] = (uint8_t)p->vrtp_ssrc;
    memcpy(rtp + 12, payload, (size_t)plen);
    int pl = srtp_protect(&p->srtp_tx_v, rtp, 12 + plen, prot);
    if (pl > 0) pace_enqueue(p, prot, pl);
}

static void vp8_frame_cb(void *ud, const uint8_t *frame, int flen) {
    account_t *a = ud; xp_priv *p = tri_account_priv(a);
#ifdef TRI_MUJI_MESH
    int meshv = mesh_video_active(p);
#else
    int meshv = 0;
#endif
    if (!p->vid_sending || (!p->ice && !meshv)) return;
    vp8_frag frags[VP8_MAX_FRAG];
    int nf = vp8_packetize(frame, flen, 1100, frags, VP8_MAX_FRAG);
    if (nf <= 0) return;
    p->vid_frames++;
    if (p->vtx_prev_on && !vdec_try(a, &p->vtx_dec, &p->vtx_dec_tried, TRI_VIDEO_SELF, "VP8", frame, flen))
        vsink_vp8(&p->vtx_prev, a, TRI_VIDEO_SELF, frame, flen);
    uint32_t ts = p->vrtp_ts; p->vrtp_ts += 6000;
    for (int i = 0; i < nf; i++) {
        if (p->ice) send_video_rtp(a, frags[i].data, frags[i].len, frags[i].marker, ts);
#ifdef TRI_MUJI_MESH
        if (meshv) mesh_video_send(a, frags[i].data, frags[i].len, frags[i].marker, ts);
#endif
    }
}

static void h264_nal_cb(void *ud, const uint8_t *nal, int nlen) {
    account_t *a = ud; xp_priv *p = tri_account_priv(a);
#ifdef TRI_MUJI_MESH
    int meshv = mesh_video_active(p);
#else
    int meshv = 0;
#endif
    if (!p->vid_sending || (!p->ice && !meshv) || nlen < 1) return;
    int type = h264_nal_type(nal, nlen);
    if (type == 9) { p->vrtp_ts += 6000; return; }
    h264_frag fr[H264_MAX_FRAG];
    int nf = h264_packetize(nal, nlen, 1100, fr, H264_MAX_FRAG);
    if (nf <= 0) return;
    int vcl = (type >= 1 && type <= 5);
    if (vcl) p->vid_frames++;
    if (p->vtx_prev_on) {
        static const uint8_t sc[4] = { 0, 0, 0, 1 };
        if (p->vtx_nalcap < nlen + 4) {
            uint8_t *nb = realloc(p->vtx_nalbuf, (size_t)nlen + 4);
            if (nb) { p->vtx_nalbuf = nb; p->vtx_nalcap = nlen + 4; }
        }
        if (p->vtx_nalcap >= nlen + 4) {
            memcpy(p->vtx_nalbuf, sc, 4); memcpy(p->vtx_nalbuf + 4, nal, (size_t)nlen);
            if (!vdec_try(a, &p->vtx_dec, &p->vtx_dec_tried, TRI_VIDEO_SELF, "H264", p->vtx_nalbuf, nlen + 4))
                vsink_h264(&p->vtx_prev, a, TRI_VIDEO_SELF, p->vtx_nalbuf, nlen + 4);
        }
    }
    for (int i = 0; i < nf; i++) {
        int marker = vcl && i == nf - 1;
        if (p->ice) send_video_rtp(a, fr[i].data, fr[i].len, marker, p->vrtp_ts);
#ifdef TRI_MUJI_MESH
        if (meshv) mesh_video_send(a, fr[i].data, fr[i].len, marker, p->vrtp_ts);
#endif
    }
}
static void vid_readable_cb(void *ud, int fd) {
    (void)fd; account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (!p->vid_sending) return;
    uint8_t buf[65536];
    ssize_t n = read(p->vid_fd, buf, sizeof buf);
    if (n <= 0) { if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) call_video_stop(a); return; }
    int rc = 0;
    if (p->vid_h264)     rc = h264_feed(p->vid_h264, buf, (int)n, h264_nal_cb, a);
    else if (p->vid_ivf) rc = ivf_feed(p->vid_ivf, buf, (int)n, vp8_frame_cb, a);
    if (rc < 0) call_video_stop(a);
}

static void video_enc_opts(const char *codec, char *out, size_t n) {
    if (!strcmp(codec, "H264"))
        snprintf(out, n, "-c:v libx264 -profile:v baseline -level 3.1 -pix_fmt yuv420p -tune zerolatency "
                 "-b:v 1000k -g 15 -keyint_min 15 -x264-params slices=1:sliced-threads=0:aud=1 -f h264");
    else

        snprintf(out, n, "-c:v libvpx -pix_fmt yuv420p -b:v 1000k -deadline realtime -cpu-used 8 -g 15 -keyint_min 15 -f ivf");
}

#ifdef TRI_X11

static int video_spawn_screen_x11(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    p->x11 = x11cap_open(1280);
    if (!p->x11) return tri_set_error("xmpp: no X11 display for screen capture (set DISPLAY, or this is a Wayland session)");
    int w = 0, h = 0; x11cap_dims(p->x11, &w, &h);
    p->vid_raw_cap = w * h * 4;
    p->vid_raw = malloc((size_t)p->vid_raw_cap);
    if (!p->vid_raw) { x11cap_close(p->x11); p->x11 = NULL; return tri_set_error("xmpp: out of memory for screen capture"); }
    p->vid_raw_len = p->vid_raw_off = 0; p->vid_grab_last = 0;
    char enc[400]; video_enc_opts(p->vid_codec, enc, sizeof enc);
    char cmd[700];
    snprintf(cmd, sizeof cmd, "exec ffmpeg -loglevel error -f rawvideo -pix_fmt bgra -s %dx%d -framerate 15 -i - %s - 2>%s",
             w, h, enc, p->vid_errlog);
    signal(SIGPIPE, SIG_IGN);
    p->vid_pid = spawn_pipe2(cmd, &p->vid_in_fd, &p->vid_fd);
    if (p->vid_pid < 0) { free(p->vid_raw); p->vid_raw = NULL; x11cap_close(p->x11); p->x11 = NULL;
                          return tri_set_error("xmpp: could not spawn ffmpeg encoder for screen capture"); }
    int fl;
    if ((fl = fcntl(p->vid_in_fd, F_GETFL, 0)) >= 0) fcntl(p->vid_in_fd, F_SETFL, fl | O_NONBLOCK);
    if ((fl = fcntl(p->vid_fd,    F_GETFL, 0)) >= 0) fcntl(p->vid_fd,    F_SETFL, fl | O_NONBLOCK);
#ifdef F_SETPIPE_SZ
    fcntl(p->vid_in_fd, F_SETPIPE_SZ, p->vid_raw_cap);
#endif
    tri_core_add_fd(tri_account_core(a), p->vid_fd, vid_readable_cb, a);
    tri_log(tri_account_core(a), "video: screenshare via native X11 capture %dx%d -> %s (%s)",
            w, h, !strcmp(p->vid_codec, "H264") ? "libx264" : "libvpx", p->vid_codec);
    return 0;
}
#endif

static int video_spawn_encoder(account_t *a, int src) {
    xp_priv *p = tri_account_priv(a);
    const char *codec = p->vid_codec;
    if (!strcmp(codec, "H264")) { p->vid_h264 = calloc(1, sizeof *p->vid_h264); if (p->vid_h264) h264_reader_reset(p->vid_h264); }
    else                        { p->vid_ivf  = calloc(1, sizeof *p->vid_ivf);  if (p->vid_ivf)  ivf_reset(p->vid_ivf); }
    if (!p->vid_h264 && !p->vid_ivf) return -1;
    snprintf(p->vid_errlog, sizeof p->vid_errlog, "/tmp/trichat-vid-%d.log", (int)getpid());
#ifdef TRI_X11
    if (src == 2) {
        if (video_spawn_screen_x11(a) != 0) { free(p->vid_ivf); p->vid_ivf = NULL; free(p->vid_h264); p->vid_h264 = NULL; return -1; }
        return 0;
    }
#endif
    const char *disp = getenv("DISPLAY"); if (!disp || !disp[0]) disp = ":0";
    char input[200];

    if (src == 2) snprintf(input, sizeof input, "-f x11grab -framerate 15 -i %s -vf 'crop=trunc(iw/2)*2:trunc(ih/2)*2'", disp);
    else          snprintf(input, sizeof input, "-f v4l2 -framerate 15 -i /dev/video0");
    char enc[400]; video_enc_opts(codec, enc, sizeof enc);
    char cmd[800];
    snprintf(cmd, sizeof cmd, "ffmpeg -loglevel error %s %s - 2>%s", input, enc, p->vid_errlog);
    p->vid_pipe = popen(cmd, "r");
    if (!p->vid_pipe) { free(p->vid_ivf); p->vid_ivf = NULL; free(p->vid_h264); p->vid_h264 = NULL; return -1; }
    tri_log(tri_account_core(a), "video: %s via %s (%s, DISPLAY=%s)", src == 2 ? "screenshare" : "camera",
            !strcmp(codec, "H264") ? "libx264" : "libvpx", codec, disp);
    p->vid_fd = fileno(p->vid_pipe);
    int fl = fcntl(p->vid_fd, F_GETFL, 0); if (fl >= 0) fcntl(p->vid_fd, F_SETFL, fl | O_NONBLOCK);
    tri_core_add_fd(tri_account_core(a), p->vid_fd, vid_readable_cb, a);
    return 0;
}
#ifdef TRI_X11

static void screen_selfpreview(account_t *a, const uint8_t *bgra, int sw, int sh) {
    xp_priv *p = tri_account_priv(a);
    if (sw <= 0 || sh <= 0) return;
    double sc = (double)VDEC_W / sw; if ((double)VDEC_H / sh < sc) sc = (double)VDEC_H / sh;
    int tw = (int)(sw * sc), th = (int)(sh * sc);
    if (tw < 1) tw = 1;
    if (th < 1) th = 1;
    if (!p->vid_selfprev) { p->vid_selfprev = malloc((size_t)VDEC_W * VDEC_H * 4); if (!p->vid_selfprev) return; }
    uint8_t *dst = p->vid_selfprev;
    for (int y = 0; y < th; y++) {
        const uint8_t *srow = bgra + (size_t)((y * sh) / th) * sw * 4;
        uint8_t *drow = dst + (size_t)y * tw * 4;
        for (int x = 0; x < tw; x++) {
            const uint8_t *sp = srow + (size_t)((x * sw) / tw) * 4;
            drow[x * 4 + 0] = sp[2];
            drow[x * 4 + 1] = sp[1];
            drow[x * 4 + 2] = sp[0];
            drow[x * 4 + 3] = 255;
        }
    }
    tri_call_video_publish(tri_account_core(a), tri_account_key(a), TRI_VIDEO_SELF, tw, th, dst);
}
#endif

static void screen_grab_pump(account_t *a) {
#ifdef TRI_X11
    xp_priv *p = tri_account_priv(a);
    if (!p->x11 || p->vid_in_fd < 0) return;
    while (p->vid_raw_off < p->vid_raw_len) {
        ssize_t w = write(p->vid_in_fd, p->vid_raw + p->vid_raw_off, (size_t)(p->vid_raw_len - p->vid_raw_off));
        if (w > 0) { p->vid_raw_off += (int)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        call_video_stop(a); return;
    }
    double t = now_s();
    if (t - p->vid_grab_last < 1.0 / 15.0) return;
    int n = x11cap_grab(p->x11, p->vid_raw, p->vid_raw_cap);
    if (n > 0) { p->vid_raw_len = n; p->vid_raw_off = 0; p->vid_grab_last = t;
                 int cw = 0, ch = 0; x11cap_dims(p->x11, &cw, &ch);
                 screen_selfpreview(a, p->vid_raw, cw, ch);
                 while (p->vid_raw_off < p->vid_raw_len) {
                     ssize_t w = write(p->vid_in_fd, p->vid_raw + p->vid_raw_off, (size_t)(p->vid_raw_len - p->vid_raw_off));
                     if (w > 0) { p->vid_raw_off += (int)w; continue; }
                     break;
                 } }
#else
    (void)a;
#endif
}

static void call_video_start(account_t *a, int src) {
    xp_priv *p = tri_account_priv(a);
    if (p->vid_sending || !p->media_ready || !p->dtls) return;
    uint8_t km[128]; int kl = dtls_srtp_keys(p->dtls, km, sizeof km);
    if (kl < 60) return;
    const uint8_t *ck = km, *sk = km + 16, *cs = km + 32, *ss = km + 46;
    int we_client = !strcmp(p->call.setup, "active");
    const uint8_t *txk = we_client ? ck : sk, *txs = we_client ? cs : ss;

    if (!p->vid_codec[0]) { emit(a, TRI_EV_ERROR, p->call.peer, "[call] no shared video codec with the peer - can't send video"); return; }
    const char *ffenc = !strcmp(p->vid_codec, "H264") ? "libx264" : "libvpx";
    if (!ffmpeg_has_encoder(ffenc)) {
        emit(a, TRI_EV_ERROR, p->call.peer, "[call] no usable video encoder in ffmpeg (need libx264 or libvpx)"); return; }
    if (srtp_init(&p->srtp_tx_v, txk, txs) != 0) return;

    p->pace_q = malloc((size_t)PACE_SLOTS * SRTP_MAX_PACKET);
    p->pace_len = malloc(PACE_SLOTS * sizeof *p->pace_len);
    if (!p->pace_q || !p->pace_len) { free(p->pace_q); p->pace_q = NULL; free(p->pace_len); p->pace_len = NULL;
        srtp_clear(&p->srtp_tx_v); emit(a, TRI_EV_ERROR, p->call.peer, "[call] out of memory for video pacing"); return; }
    p->pace_head = p->pace_count = p->pace_dropped = 0;
    p->pace_budget = 0; p->pace_last = now_s(); p->pace_rate = 2.5 * 1000000.0 / 8.0;
    p->vrtp_ssrc = p->call.vssrc ? p->call.vssrc : ((unsigned)rand() | 1u);
    p->vid_pt = (p->call.nvpt > 0 && p->call.vpts[0].id > 0) ? p->call.vpts[0].id : 96;
    p->vid_frames = 0; p->vid_key_last = 0;
    if (video_spawn_encoder(a, src) != 0) {
        free(p->pace_q); p->pace_q = NULL; free(p->pace_len); p->pace_len = NULL; srtp_clear(&p->srtp_tx_v);
        char eb[220]; snprintf(eb, sizeof eb, "[call] %s", tri_last_error());
        emit(a, TRI_EV_ERROR, p->call.peer, eb); return; }
    p->vid_sending = 1;

    p->vtx_prev_on = (src != 2);
    char pb[256]; bare_jid(p->call.peer, pb, sizeof pb);
    char m[200]; snprintf(m, sizeof m, "[call] %s to %s", src == 2 ? "screensharing" : "sending video", pb);
    emit(a, TRI_EV_STATUS, pb, m);
}

static void rtcp_scan_feedback(account_t *a, const uint8_t *b, int n) {
    xp_priv *p = tri_account_priv(a);
    int off = 0;
    while (off + 4 <= n) {
        int fmt = b[off] & 0x1f, pt = b[off + 1];
        int plen = (((b[off + 2] << 8) | b[off + 3]) + 1) * 4;
        if (plen < 4 || off + plen > n) break;
        if ((pt == 206 && (fmt == 1 || fmt == 4)) ||
            (pt == 205 && fmt == 1)) {
            double now = now_s();
            if (now - p->vid_key_last > 2.0) {
                p->vid_key_last = now;
                tri_log(tri_account_core(a), "video: peer reported loss (RTCP PLI/FIR) - awaiting next scheduled keyframe");
            }
            return;
        }
        off += plen;
    }
}

static void video_rx_feed(account_t *a, const uint8_t *data, int len) {
    xp_priv *p = tri_account_priv(a);
    if (!p->srtp_rx_v.ready) return;
    uint8_t rtp[SRTP_MAX_PACKET];
    int rl = srtp_unprotect(&p->srtp_rx_v, data, len, rtp);
    if (rl < 12) return;
    int hl = srtp_rtp_header_len(rtp, rl);
    if (rl <= hl) return;
    int marker = rtp[1] & 0x80;
    p->vrx_peer_ssrc = ((uint32_t)rtp[8] << 24) | ((uint32_t)rtp[9] << 16) | ((uint32_t)rtp[10] << 8) | rtp[11];

    uint16_t seq = (uint16_t)((rtp[2] << 8) | rtp[3]);
    if (p->vrx_have_seq && seq != (uint16_t)(p->vrx_last_seq + 1)) {
        if (p->vrx_vp8)  { p->vrx_vp8->in_frame = 0; p->vrx_vp8->len = 0; }
        if (p->vrx_h264) { p->vrx_h264->active = 0; p->vrx_h264->len = 0; }
        p->vrx_want_key = 1; p->vrx_dropped++;
    }
    p->vrx_last_seq = seq; p->vrx_have_seq = 1;

    const uint8_t *pl = rtp + hl; int plen = rl - hl;
    const char *codec = (p->call.nvpt > 0) ? p->call.vpts[0].name : "VP8";
    if (!strcasecmp(codec, "H264")) {
        if (!p->vrx_h264) { p->vrx_h264 = calloc(1, sizeof *p->vrx_h264); if (!p->vrx_h264) return; h264_depkt_reset(p->vrx_h264); }
        static uint8_t out[H264_BUF];
        int wrote = h264_depacketize(p->vrx_h264, pl, plen, out, (int)sizeof out);
        if (wrote > 0) { p->vrx_frames++;
            if (!vdec_try(a, &p->vrx_dec, &p->vrx_dec_tried, TRI_VIDEO_REMOTE, "H264", out, wrote))
                vsink_h264(&p->vrx, a, TRI_VIDEO_REMOTE, out, wrote); }
    } else {
        if (!p->vrx_vp8) { p->vrx_vp8 = calloc(1, sizeof *p->vrx_vp8); if (!p->vrx_vp8) return; }
        const uint8_t *frame; int flen;
        if (vp8_depacketize(p->vrx_vp8, pl, plen, marker, &frame, &flen)) { p->vrx_frames++;
            if (!vdec_try(a, &p->vrx_dec, &p->vrx_dec_tried, TRI_VIDEO_REMOTE, "VP8", frame, flen))
                vsink_vp8(&p->vrx, a, TRI_VIDEO_REMOTE, frame, flen); }
    }
}

static void video_send_pli(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->ice || !p->srtp_tx.ready || !p->vrx_peer_ssrc) return;
    double t = now_s();
    if (t - p->vrx_pli_last < 0.5) return;
    p->vrx_pli_last = t;
    uint32_t me = p->call.vssrc ? p->call.vssrc : p->call.ssrc;
    uint8_t pli[12] = {
        0x81, 206, 0, 2,
        (uint8_t)(me >> 24), (uint8_t)(me >> 16), (uint8_t)(me >> 8), (uint8_t)me,
        (uint8_t)(p->vrx_peer_ssrc >> 24), (uint8_t)(p->vrx_peer_ssrc >> 16),
        (uint8_t)(p->vrx_peer_ssrc >> 8), (uint8_t)p->vrx_peer_ssrc };
    uint8_t prot[SRTP_MAX_PACKET];
    int pl = srtcp_protect(&p->srtp_tx, pli, 12, prot);
    if (pl > 0) ice_send(p->ice, prot, pl);
}

static void call_media_cb(void *ud, const uint8_t *data, int len) {
    account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (len <= 0) return;
    if (data[0] >= 20 && data[0] <= 63) {
        if (p->dtls) { dtls_srtp_feed(p->dtls, data, len); call_dtls_progress(a); }
    } else if (data[0] >= 128 && data[0] <= 191 && p->media_ready) {
        if (len >= 2 && data[1] >= 192 && data[1] <= 223) {
            uint8_t rtcp[SRTP_MAX_PACKET];
            int rn = srtcp_unprotect(&p->srtp_rx, data, len, rtcp);
            if (rn >= 8) rtcp_scan_feedback(a, rtcp, rn);
            return;
        }

        if (p->call.has_video && p->call.nvpt > 0 && len >= 2 && (data[1] & 0x7f) == p->call.vpts[0].id) {
            video_rx_feed(a, data, len);
            return;
        }
        p->rx_pkts++;
        if (p->rx_pkts <= 8)
            tri_log(tri_account_core(a), "rx pkt#%d len=%d b0=%02x pt=%d", p->rx_pkts, len, data[0], len >= 2 ? (data[1] & 0x7f) : -1);
        uint8_t rtp[SRTP_MAX_PACKET];
        int rl = srtp_unprotect(&p->srtp_rx, data, len, rtp);
        if (rl < 12) { p->rx_authfail++; return; }
        int hl = srtp_rtp_header_len(rtp, rl);
        if (rl <= hl) return;
        int16_t pcm[5760];
        int samples = opus_decode(p->odec, rtp + hl, rl - hl, pcm, 5760, 0);
        if (samples > 0) { p->rx_decoded++; if (p->play) tri_audio_write(p->play, pcm, samples); }
        else p->rx_decfail++;
    }
}

static int call_start_dtls(account_t *a, int dtls_client, const char *setup) {
    xp_priv *p = tri_account_priv(a);
    if (p->dtls) { dtls_srtp_free(p->dtls); p->dtls = NULL; }
    p->dtls = dtls_srtp_new(dtls_client, dtls_send_via_ice, a);
    if (!p->dtls) return tri_set_error("xmpp: DTLS-SRTP setup failed");
    p->dtls_started = 0; p->dtls_secured = 0;
    snprintf(p->call.setup, sizeof p->call.setup, "%s", setup);
    snprintf(p->call.fp_hash, sizeof p->call.fp_hash, "sha-256");
    snprintf(p->call.fingerprint, sizeof p->call.fingerprint, "%s", dtls_srtp_fingerprint(p->dtls));
    return 0;
}

static void ice_cands_into(jingle_session *js, ice_agent *ice, int from) {
    js->ncand = 0;
    int total = ice_candidate_count(ice);
    for (int i = from; i < total && js->ncand < JINGLE_MAX_CAND; i++) {
        ice_cand c; ice_candidate_get(ice, i, &c);
        jingle_candidate *jc = &js->cand[js->ncand++];
        snprintf(jc->foundation, sizeof jc->foundation, "%s", c.foundation);
        jc->component = c.component;
        snprintf(jc->protocol, sizeof jc->protocol, "udp");
        snprintf(jc->ip, sizeof jc->ip, "%s", c.ip);
        jc->port = c.port; jc->priority = (int)c.priority;
        snprintf(jc->type, sizeof jc->type, "%s", c.type);
    }
}

static void ice_trickle(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->ice || ice_candidate_count(p->ice) <= p->ice_sent) return;
    jingle_session ti; memset(&ti, 0, sizeof ti);
    snprintf(ti.sid, sizeof ti.sid, "%s", p->call.sid);
    snprintf(ti.peer, sizeof ti.peer, "%s", p->call.peer);

    const char *primary = (p->call.has_video && p->call.video_first && p->call.video_name[0])
                          ? p->call.video_name
                          : (p->call.content_name[0] ? p->call.content_name : "audio");
    snprintf(ti.content_name, sizeof ti.content_name, "%s", primary);
    snprintf(ti.ufrag, sizeof ti.ufrag, "%s", ice_ufrag(p->ice));
    snprintf(ti.pwd, sizeof ti.pwd, "%s", ice_pwd(p->ice));
    ice_cands_into(&ti, p->ice, p->ice_sent);
    for (int i = 0; i < ti.ncand; i++) tri_log(tri_account_core(a), "ice trickle local %s:%d (%s)", ti.cand[i].ip, ti.cand[i].port, ti.cand[i].type);
    p->ice_sent = ice_candidate_count(p->ice);
    char buf[2048], iqid[32]; snprintf(iqid, sizeof iqid, "jgti%u", ++p->jingle_seq);
    if (jingle_build_transport_info(buf, sizeof buf, p->jid, &ti, iqid)) xs_send(a, buf);
}
static void ice_pump(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->ice) return;
    ice_trickle(a);
    if (ice_state(p->ice) == ICE_CONNECTED && !p->ice_connected) {
        p->ice_connected = 1;
        ice_cand la, ra; if (ice_selected(p->ice, &la, &ra)) tri_log(tri_account_core(a), "ice CONNECTED - selected remote %s:%d", ra.ip, ra.port);
        char pb[256]; bare_jid(p->call.peer, pb, sizeof pb);
        char m[300]; snprintf(m, sizeof m, "[call] connection established with %s - securing (DTLS)", pb);
        emit(a, TRI_EV_STATUS, pb, m);
    }

    if (ice_state(p->ice) == ICE_CONNECTED && p->dtls && !p->dtls_started) {
        p->dtls_started = 1;
        dtls_srtp_start(p->dtls);
        call_dtls_progress(a);
    }
}
static void ice_readable_cb(void *ud, int fd) {
    (void)fd; account_t *a = ud; xp_priv *p = tri_account_priv(a);
    if (p && p->ice) { ice_on_readable(p->ice); ice_pump(a); }
}
static void call_end_ice(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    call_mic_stop(a);
    call_video_stop(a);
    vsink_close(&p->vrx, tri_account_core(a)); vsink_close(&p->vtx_prev, tri_account_core(a)); p->vtx_prev_on = 0;
    if (p->vrx_dec) { tri_core_remove_fd(tri_account_core(a), tri_vdec_async_fd(p->vrx_dec));
                      tri_vdec_async_free(p->vrx_dec); p->vrx_dec = NULL; } p->vrx_dec_tried = 0;
    tri_call_video_clear(tri_account_core(a), tri_account_key(a), -1);
    free(p->vrx_vp8); p->vrx_vp8 = NULL;
    free(p->vrx_h264); p->vrx_h264 = NULL;
    if (p->srtp_rx_v.ready) srtp_clear(&p->srtp_rx_v);
    p->vrx_have_seq = 0; p->vrx_want_key = 0; p->vrx_peer_ssrc = 0; p->vrx_pli_last = 0;
    p->vrx_frames = p->vrx_dropped = 0;
    p->want_video = 0; p->vid_codec[0] = '\0';
    if (p->sb_pcm) { free(p->sb_pcm); p->sb_pcm = NULL; p->sb_n = p->sb_pos = 0; p->sb_playing = 0; }
    if (p->media_ready) {
        srtp_clear(&p->srtp_tx); srtp_clear(&p->srtp_rx);
        if (p->oenc) { opus_encoder_destroy(p->oenc); p->oenc = NULL; }
        if (p->odec) { opus_decoder_destroy(p->odec); p->odec = NULL; }
        if (p->play) { tri_audio_close(p->play); p->play = NULL; }
        p->media_ready = 0;
    }
    if (p->dtls) { dtls_srtp_free(p->dtls); p->dtls = NULL; p->dtls_started = 0; p->dtls_secured = 0; }
    if (!p->ice) return;
    tri_core_remove_fd(tri_account_core(a), ice_fd(p->ice));
    ice_free(p->ice); p->ice = NULL; p->ice_sent = 0; p->ice_connected = 0;
}

static int call_start_ice(account_t *a, int controlling) {
    xp_priv *p = tri_account_priv(a);
    call_end_ice(a);
    p->ice = ice_new(controlling);
    if (!p->ice) return tri_set_error("xmpp: ICE socket setup failed");
    ice_set_app_cb(p->ice, call_media_cb, a);
    tri_core_add_fd(tri_account_core(a), ice_fd(p->ice), ice_readable_cb, a);
    if (p->turn_host[0]) {
        char tip[46]; char tport[8]; snprintf(tport, sizeof tport, "%d", p->turn_port);
        if (resolve_ipv4(p->turn_host, tport, tip, sizeof tip) == 0) {
            ice_set_turn(p->ice, tip, p->turn_port, p->turn_user, p->turn_pass, "");
            tri_log(tri_account_core(a), "ice: TURN %s:%d - allocating relay candidate", tip, p->turn_port);
        } else tri_log(tri_account_core(a), "ice: TURN resolve FAILED for %s - no relay candidate", p->turn_host);
    }
    char sip[46]; int sport = 3478;
    if (resolve_stun(sip, sizeof sip, &sport) == 0) { ice_gather(p->ice, sip, sport); tri_log(tri_account_core(a), "ice: STUN %s:%d - gathering", sip, sport); }
    else { ice_gather(p->ice, NULL, 0); tri_log(tri_account_core(a), "ice: STUN resolve FAILED - host candidate only"); }
    for (int i = 0; i < ice_candidate_count(p->ice); i++) { ice_cand c; ice_candidate_get(p->ice, i, &c);
        tri_log(tri_account_core(a), "ice local cand %s:%d (%s)", c.ip, c.port, c.type); }
    snprintf(p->call.ufrag, sizeof p->call.ufrag, "%s", ice_ufrag(p->ice));
    snprintf(p->call.pwd, sizeof p->call.pwd, "%s", ice_pwd(p->ice));
    ice_cands_into(&p->call, p->ice, 0);
    p->ice_sent = ice_candidate_count(p->ice);
    return 0;
}

static void call_feed_remote(account_t *a, const jingle_session *js) {
    xp_priv *p = tri_account_priv(a);
    if (!p->ice) return;
    if (js->ufrag[0]) ice_set_remote_creds(p->ice, js->ufrag, js->pwd);
    for (int i = 0; i < js->ncand; i++) {
        int ok = ice_add_remote(p->ice, js->cand[i].ip, js->cand[i].port, (unsigned)js->cand[i].priority, js->cand[i].type);
        tri_log(tri_account_core(a), "ice remote cand %s:%d (%s) -> %s",
                js->cand[i].ip, js->cand[i].port, js->cand[i].type, ok ? "added" : "skipped (dup/IPv6)");
    }
}

static int call_do_initiate(account_t *a, const char *peer_full, const char *sid) {
    xp_priv *p = tri_account_priv(a);
    memset(&p->call, 0, sizeof p->call);
    snprintf(p->call.peer, sizeof p->call.peer, "%s", peer_full);
    snprintf(p->call.sid, sizeof p->call.sid, "%s", sid);
    snprintf(p->call.content_name, sizeof p->call.content_name, "audio");
    p->call.pts[0] = (jingle_payload){ 111, "opus", 48000, 2 }; p->call.npt = 1;
    p->call.ssrc = (unsigned)rand() | 1u; snprintf(p->call.cname, sizeof p->call.cname, "trichat%u", p->call.ssrc);
    if (p->want_video) {
        int nv = 0;
        if (ffmpeg_has_encoder("libvpx") && nv < JINGLE_MAX_PT) {
            p->call.vpts[nv].id = 96; snprintf(p->call.vpts[nv].name, sizeof p->call.vpts[nv].name, "VP8");
            p->call.vpts[nv].clockrate = 90000; p->call.vpts[nv].channels = 1; nv++;
        }
        if (ffmpeg_has_encoder("libx264") && nv < JINGLE_MAX_PT) {
            p->call.vpts[nv].id = 97; snprintf(p->call.vpts[nv].name, sizeof p->call.vpts[nv].name, "H264");
            p->call.vpts[nv].clockrate = 90000; p->call.vpts[nv].channels = 1; nv++;
        }
        if (nv == 0) {
            emit(a, TRI_EV_ERROR, peer_full, "[call] no video encoder - aborting (would mismatch the JMI video offer)");
            p->want_video = 0;
            return tri_set_error("xmpp: no video encoder to fulfill the promised video call");
        }
        p->call.nvpt = nv; p->call.has_video = 1;
        snprintf(p->call.video_name, sizeof p->call.video_name, "1");
        p->call.vssrc = ((unsigned)rand() << 1) | 1u;
        snprintf(p->vid_codec, sizeof p->vid_codec, "%s", p->call.vpts[0].name);
    }
    if (call_start_ice(a, 1) != 0) return -1;
    if (call_start_dtls(a, 0, "actpass") != 0) { call_end_ice(a); return -1; }
    p->call.state = JINGLE_OUTGOING;
    char iqid[32]; snprintf(iqid, sizeof iqid, "jgin%u", ++p->jingle_seq);
    char buf[4096];
    if (!jingle_build_initiate(buf, sizeof buf, p->jid, &p->call, iqid)) { call_end_ice(a); return tri_set_error("xmpp: jingle initiate too large"); }
    if (xs_send(a, buf) != 0) { call_end_ice(a); return -1; }
    return 0;
}

static int call_do_accept(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->ice) return tri_set_error("xmpp: call has no ICE agent");
    int opi = -1;
    for (int i = 0; i < p->call.npt; i++) if (!strcasecmp(p->call.pts[i].name, "opus")) { opi = i; break; }
    if (opi >= 0) { p->call.pts[0] = p->call.pts[opi]; }
    else          { p->call.pts[0] = (jingle_payload){ 111, "opus", 48000, 2 }; }
    p->call.npt = 1;
    p->call.ssrc = (unsigned)rand() | 1u; snprintf(p->call.cname, sizeof p->call.cname, "trichat%u", p->call.ssrc);
    if (p->call.has_video) {
        int vi = -1;
        for (int i = 0; i < p->call.nvpt; i++) if (can_encode_codec(p->call.vpts[i].name)) { vi = i; break; }
        if (vi >= 0) { p->call.vpts[0] = p->call.vpts[vi];
                       snprintf(p->vid_codec, sizeof p->vid_codec, "%s", strcasecmp(p->call.vpts[0].name, "H264") ? "VP8" : "H264"); }
        else         { p->vid_codec[0] = '\0'; }
        p->call.nvpt = (p->call.nvpt > 0) ? 1 : 0;
        p->call.vssrc = ((unsigned)rand() << 1) | 1u;
        if (!p->call.video_name[0]) snprintf(p->call.video_name, sizeof p->call.video_name, "1");
    }
    p->call.state = JINGLE_ACTIVE;
    char iqid[32]; snprintf(iqid, sizeof iqid, "jgac%u", ++p->jingle_seq);
    char buf[4096];
    if (!jingle_build_accept(buf, sizeof buf, p->jid, &p->call, iqid)) return tri_set_error("xmpp: jingle accept too large");
    if (xs_send(a, buf) != 0) return -1;
    ice_start_checks(p->ice);
    ice_pump(a);
    char pb[256]; bare_jid(p->call.peer, pb, sizeof pb);
    char m[300]; snprintf(m, sizeof m, "[call] answered %s - negotiating media path", pb);
    emit(a, TRI_EV_STATUS, pb, m);
    return 0;
}

static void handle_jmi(account_t *a, const char *s) {
    xp_priv *p = tri_account_priv(a);
    if (p->state != ST_ONLINE) return;
    tri_log(tri_account_core(a), "jmi<- %.400s", s);
    char from[256] = ""; xml_attr(s, "from", from, sizeof from);
    char barefrom[256]; bare_jid(from, barefrom, sizeof barefrom);

    if (strstr(s, "<propose")) {
        const char *e = strstr(s, "<propose"); char id[64] = ""; xml_attr(e, "id", id, sizeof id);
        if (!id[0]) return;
        snprintf(p->jmi_id, sizeof p->jmi_id, "%s", id);
        snprintf(p->jmi_peer, sizeof p->jmi_peer, "%s", from);
        p->jmi_in = 1; p->jmi_out = 0; p->auto_accept = 0;
        int vid = strstr(s, "media='video'") || strstr(s, "media=\"video\"");
        char m[400]; snprintf(m, sizeof m, "[call] incoming %s call from %s - /accept or /hangup", vid ? "video" : "voice", barefrom);
        emit(a, TRI_EV_STATUS, barefrom, m);
        call_signal(a, "incoming", barefrom, vid);
    } else if (strstr(s, "<proceed")) {
        const char *e = strstr(s, "<proceed"); char id[64] = ""; xml_attr(e, "id", id, sizeof id);
        if (p->jmi_out && !strcmp(id, p->jmi_id)) {
            p->jmi_out = 0;
            if (call_do_initiate(a, from, id) != 0) emit(a, TRI_EV_ERROR, barefrom, tri_last_error());
        }
    } else if (strstr(s, "<reject") || strstr(s, "<retract")) {
        const char *e = strstr(s, "<reject"); if (!e) e = strstr(s, "<retract");
        char id[64] = ""; xml_attr(e, "id", id, sizeof id);
        if (p->jmi_id[0] && !strcmp(id, p->jmi_id)) {
            char m[300]; snprintf(m, sizeof m, "[call] call with %s ended", barefrom);
            emit(a, TRI_EV_STATUS, barefrom, m);
            call_signal(a, "ended", barefrom, 0);
            call_end_ice(a); memset(&p->call, 0, sizeof p->call);
            p->jmi_in = p->jmi_out = p->auto_accept = 0; p->jmi_id[0] = 0;
        }
    }
}

static void handle_jingle(account_t *a, const char *s, const char *iq_id) {
    xp_priv *p = tri_account_priv(a);
    char from[256] = ""; xml_attr(s, "from", from, sizeof from);
    if (from[0] && iq_id && iq_id[0]) xs_sendf(a, "<iq type='result' id='%s' to='%s'/>", iq_id, from);

    jingle_session js; char action[32];
    if (!jingle_parse(s, &js, action, sizeof action)) return;
    tri_log(tri_account_core(a), "jingle<- %s: %.800s", action, s);
#ifdef TRI_MUJI_MESH
    if (mesh_route_jingle(a, from, &js, action)) return;
#endif
    char peerbare[256]; bare_jid(from, peerbare, sizeof peerbare);

    if (!strcmp(action, "session-initiate")) {
        if (p->call.state != JINGLE_ENDED && strcmp(p->call.sid, js.sid)) {
            snprintf(js.peer, sizeof js.peer, "%s", from);
            char tb[512]; if (jingle_build_terminate(tb, sizeof tb, p->jid, &js, "busy", "jgbusy")) xs_send(a, tb);
            return;
        }
        jingle_session peer = js;
        p->call = js;
        snprintf(p->call.peer, sizeof p->call.peer, "%s", from);
        if (call_start_ice(a, 0) == 0) {
            call_feed_remote(a, &peer);
            call_start_dtls(a, 1, "active");
            if (p->dtls && peer.fingerprint[0]) dtls_srtp_set_peer_fingerprint(p->dtls, peer.fingerprint);
        }
        p->call.state = JINGLE_INCOMING;
        if (p->auto_accept) {
            p->auto_accept = 0;
            call_do_accept(a);
        } else {
            char m[400]; snprintf(m, sizeof m, "[call] incoming %s call from %s - /accept or /hangup", p->call.has_video ? "video" : "voice", peerbare);
            emit(a, TRI_EV_STATUS, peerbare, m);
            call_signal(a, "incoming", peerbare, p->call.has_video);
        }
    } else if (!strcmp(action, "session-accept")) {
        if (p->call.state == JINGLE_OUTGOING && !strcmp(p->call.sid, js.sid)) {
            p->call.state = JINGLE_ACTIVE;
            memcpy(p->call.pts, js.pts, sizeof js.pts); p->call.npt = js.npt;

            if (js.has_video && js.nvpt > 0) {
                p->call.has_video = 1;
                p->call.vpts[0] = js.vpts[0]; p->call.nvpt = 1;
                snprintf(p->vid_codec, sizeof p->vid_codec, "%s", strcasecmp(js.vpts[0].name, "H264") ? "VP8" : "H264");
                if (!can_encode_codec(js.vpts[0].name)) p->vid_codec[0] = '\0';
            } else {
                p->call.has_video = 0; p->call.nvpt = 0; p->vid_codec[0] = '\0'; p->want_video = 0;
                emit(a, TRI_EV_STATUS, peerbare, "[call] peer accepted audio only (declined video)");
            }
            call_feed_remote(a, &js);
            if (p->dtls && js.fingerprint[0]) dtls_srtp_set_peer_fingerprint(p->dtls, js.fingerprint);
            if (p->ice) ice_start_checks(p->ice);
            char m[300]; snprintf(m, sizeof m, "[call] %s accepted - negotiating media path", peerbare);
            emit(a, TRI_EV_STATUS, peerbare, m);
            ice_pump(a);
        }
    } else if (!strcmp(action, "session-terminate")) {
        if (p->call.sid[0] && !strcmp(p->call.sid, js.sid)) {
            char reason[64] = "";
            const char *r = strstr(s, "<reason>");
            if (r) { const char *lt = strchr(r + 8, '<'); if (lt && lt[1] != '/') sscanf(lt, "<%63[^/> ]", reason); }
            char m[320]; snprintf(m, sizeof m, "[call] call with %s ended%s%s", peerbare, reason[0] ? " - reason: " : "", reason);
            emit(a, TRI_EV_STATUS, peerbare, m);
            call_signal(a, "ended", peerbare, 0);
            if (p->ice) { char dbg[1024]; ice_debug(p->ice, dbg, sizeof dbg); tri_log(tri_account_core(a), "ice state at teardown: %s", dbg); }
            call_end_ice(a);
            memset(&p->call, 0, sizeof p->call);
        }
    } else if (!strcmp(action, "transport-info")) {
        if (p->call.sid[0] && !strcmp(p->call.sid, js.sid)) { call_feed_remote(a, &js); ice_pump(a); }
    }
}

#ifdef TRI_MUJI_MESH
static void mesh_ensure_capture(account_t *a);
static void mesh_media_init(account_t *a, mesh_peer *mp);
static void mesh_dtls_progress(account_t *a, mesh_peer *mp);
static void mesh_ice_pump(account_t *a, mesh_peer *mp);
static void mesh_video_start(account_t *a);
static void mesh_video_stop(account_t *a);
static void mesh_video_rx_feed(account_t *a, mesh_peer *mp, const uint8_t *data, int len);
static void mesh_send_pli(account_t *a, mesh_peer *mp);

static void mesh_dtls_send(void *ud, const uint8_t *data, int len) {
    mesh_peer *mp = ud; if (mp->ice) ice_send(mp->ice, data, len);
}

static void mesh_mix_add(account_t *a, mesh_peer *mp, const int16_t *pcm, int samples) {
    xp_priv *p = tri_account_priv(a);
    int cap = (int)(sizeof p->mesh_mix_acc / sizeof p->mesh_mix_acc[0]);
    if (!p->mesh_mix_play) { p->mesh_mix_play = tri_audio_open(tri_account_core(a)); if (!p->mesh_mix_play) return; }
    int off = mp->mix_off; if (off < 0) off = 0;
    if (off + samples > cap) { off = cap - samples; if (off < 0) { off = 0; samples = cap; } }
    for (int i = 0; i < samples; i++) p->mesh_mix_acc[off + i] += pcm[i];
    mp->mix_off = off + samples;
    if (off + samples > p->mesh_mix_fill) p->mesh_mix_fill = off + samples;
}
static void mesh_mix_flush(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->mesh_mixed || p->mesh_mix_fill <= 0) return;
    double t = now_s();
    if (t - p->mesh_mix_last < 0.02) return;
    p->mesh_mix_last = t;
    int chunk = p->mesh_mix_fill; if (chunk > 960) chunk = 960;
    int16_t out[960];
    for (int i = 0; i < chunk; i++) { int32_t s = p->mesh_mix_acc[i];
        out[i] = (int16_t)(s > 32767 ? 32767 : s < -32768 ? -32768 : s); }
    if (p->mesh_mix_play) tri_audio_write(p->mesh_mix_play, out, chunk);
    int rem = p->mesh_mix_fill - chunk;
    memmove(p->mesh_mix_acc, p->mesh_mix_acc + chunk, sizeof p->mesh_mix_acc[0] * (size_t)rem);
    memset(p->mesh_mix_acc + rem, 0, sizeof p->mesh_mix_acc[0] * (size_t)chunk);
    p->mesh_mix_fill = rem;
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active) continue;
        mp->mix_off -= chunk;
        if (mp->mix_off < 0) mp->mix_off = 0;
    }
}

static void mesh_media_cb(void *ud, const uint8_t *data, int len) {
    mesh_peer *mp = ud; account_t *a = mp->a;
    if (len <= 0) return;
    if (data[0] >= 20 && data[0] <= 63) {
        if (mp->dtls) { dtls_srtp_feed(mp->dtls, data, len); mesh_dtls_progress(a, mp); }
    } else if (data[0] >= 128 && data[0] <= 191 && mp->media_ready) {
        if (len >= 2 && data[1] >= 192 && data[1] <= 223) return;
        if (mp->has_video && mp->vid_pt && len >= 2 && (data[1] & 0x7f) == mp->vid_pt) {
            mesh_video_rx_feed(a, mp, data, len);
            return;
        }
        uint8_t rtp[SRTP_MAX_PACKET];
        int rl = srtp_unprotect(&mp->rx, data, len, rtp);
        if (rl < 12) return;
        int hl = srtp_rtp_header_len(rtp, rl);
        if (rl <= hl) return;
        int16_t pcm[5760];
        int samples = opus_decode(mp->dec, rtp + hl, rl - hl, pcm, 5760, 0);
        if (samples <= 0) return;

        long acc = 0; for (int i = 0; i < samples; i++) acc += pcm[i] < 0 ? -pcm[i] : pcm[i];
        if (samples > 0 && acc / samples > 500) mp->last_talk = now_s();
        if (mp->muted) return;
        xp_priv *p = tri_account_priv(a);
        if (p->mesh_mixed) mesh_mix_add(a, mp, pcm, samples);
        else if (mp->play) tri_audio_write(mp->play, pcm, samples);
    }
}
static void mesh_ice_readable_cb(void *ud, int fd) {
    (void)fd; mesh_peer *mp = ud;
    if (mp && mp->ice) { ice_on_readable(mp->ice); mesh_ice_pump(mp->a, mp); }
}

static void mesh_media_init(account_t *a, mesh_peer *mp) {
    if (mp->media_ready || !mp->dtls) return;
    uint8_t km[128]; int kl = dtls_srtp_keys(mp->dtls, km, sizeof km);
    if (kl < 60) return;
    const uint8_t *ck = km, *sk = km + 16, *cs = km + 32, *ss = km + 46;
    int we_client = !strcmp(mp->js.setup, "active");
    const uint8_t *txk = we_client ? ck : sk, *txs = we_client ? cs : ss;
    const uint8_t *rxk = we_client ? sk : ck, *rxs = we_client ? ss : cs;
    if (srtp_init(&mp->tx, txk, txs) != 0 || srtp_init(&mp->rx, rxk, rxs) != 0) return;
    int err = 0;
    xp_priv *p = tri_account_priv(a);
    mp->dec = opus_decoder_create(48000, 1, &err);
    if (!p->mesh_mixed) mp->play = tri_audio_open(tri_account_core(a));
    mp->rtp_ssrc = mp->js.ssrc ? mp->js.ssrc : (uint32_t)rand();
    mp->rtp_pt = (mp->js.npt > 0 && mp->js.pts[0].id > 0) ? mp->js.pts[0].id : 111;
    if (mp->has_video && mp->js.nvpt > 0 && mp->js.vpts[0].id > 0) {
        srtp_init(&mp->rx_v, rxk, rxs);
        srtp_init(&mp->tx_v, txk, txs);
        mp->vid_pt = mp->js.vpts[0].id;
        mp->vssrc = mp->js.vssrc ? mp->js.vssrc : ((unsigned)rand() | 1u);
        if (mp->vwhich <= 0) { if (p->mesh_vwhich_next < 2) p->mesh_vwhich_next = 2; mp->vwhich = p->mesh_vwhich_next++; }
    }
    mp->media_ready = 1;
    mesh_ensure_capture(a);
    if (p->mesh_video_src && mp->vcodec[0]) mesh_video_start(a);
    char m[360]; snprintf(m, sizeof m, "[muji] %s up with %s", mp->has_video ? "media" : "audio", mp->full);
    emit(a, TRI_EV_STATUS, mp->room, m);
}
static void mesh_dtls_progress(account_t *a, mesh_peer *mp) {
    if (!mp->dtls) return;
    if (dtls_srtp_done(mp->dtls) && !mp->dtls_secured) {
        mp->dtls_secured = 1; mesh_media_init(a, mp);
    } else if (dtls_srtp_failed(mp->dtls) && mp->dtls_started && !mp->dtls_secured) {
        char m[400]; snprintf(m, sizeof m, "[muji] DTLS with %s failed: %s", mp->full, dtls_srtp_error(mp->dtls));
        emit(a, TRI_EV_ERROR, mp->room, m);
        mp->dtls_secured = -1;
    }
}
static void mesh_ensure_capture(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p->mesh_enc) {
        int err = 0;
        p->mesh_enc = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &err);
        if (p->mesh_enc) opus_encoder_ctl(p->mesh_enc, OPUS_SET_BITRATE(24000));
    }
    if (!p->mic && !p->mesh_mic_muted) call_mic_start(a);
    p->mesh_capturing = 1;
}

static void mesh_fanout_audio(account_t *a, const int16_t *pcm, int samples) {
    xp_priv *p = tri_account_priv(a);
    if (!p->mesh_enc) return;
    uint8_t opus[1000];
    int n = opus_encode(p->mesh_enc, pcm, samples, opus, sizeof opus);
    if (n <= 0) return;
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active || !mp->media_ready) continue;
        uint8_t rtp[SRTP_MAX_PACKET], prot[SRTP_MAX_PACKET];
        rtp[0] = 0x80; rtp[1] = (uint8_t)mp->rtp_pt;
        rtp[2] = (uint8_t)(mp->rtp_seq >> 8); rtp[3] = (uint8_t)mp->rtp_seq; mp->rtp_seq++;
        rtp[4] = (uint8_t)(mp->rtp_ts >> 24); rtp[5] = (uint8_t)(mp->rtp_ts >> 16);
        rtp[6] = (uint8_t)(mp->rtp_ts >> 8);  rtp[7] = (uint8_t)mp->rtp_ts; mp->rtp_ts += (uint32_t)samples;
        rtp[8] = (uint8_t)(mp->rtp_ssrc >> 24); rtp[9] = (uint8_t)(mp->rtp_ssrc >> 16);
        rtp[10] = (uint8_t)(mp->rtp_ssrc >> 8); rtp[11] = (uint8_t)mp->rtp_ssrc;
        memcpy(rtp + 12, opus, (size_t)n);
        int pl = srtp_protect(&mp->tx, rtp, 12 + n, prot);
        if (pl > 0 && mp->ice) ice_send(mp->ice, prot, pl);
    }
}
static mesh_peer *mesh_find(xp_priv *p, const char *full) {
    for (int i = 0; i < MAX_PEERS; i++) if (p->mesh[i].active && !strcmp(p->mesh[i].full, full)) return &p->mesh[i];
    return NULL;
}
static mesh_peer *mesh_alloc(account_t *a, const char *room, const char *full) {
    xp_priv *p = tri_account_priv(a);
    mesh_peer *mp = mesh_find(p, full); if (mp) return mp;
    for (int i = 0; i < MAX_PEERS; i++) if (!p->mesh[i].active) {
        mp = &p->mesh[i]; memset(mp, 0, sizeof *mp);
        mp->active = 1; mp->a = a;
        snprintf(mp->room, sizeof mp->room, "%s", room);
        snprintf(mp->full, sizeof mp->full, "%s", full);
        return mp;
    }
    return NULL;
}
static void mesh_free_peer(account_t *a, mesh_peer *mp) {
    if (!mp->active) return;

    if (mp->vdec) { tri_core_remove_fd(tri_account_core(a), tri_vdec_async_fd(mp->vdec)); tri_vdec_async_free(mp->vdec); mp->vdec = NULL; }
    vsink_close(&mp->vrx, tri_account_core(a));
    if (mp->vwhich >= 2) tri_call_video_clear(tri_account_core(a), tri_account_key(a), mp->vwhich);
    free(mp->vrx_vp8); mp->vrx_vp8 = NULL;
    free(mp->vrx_h264); mp->vrx_h264 = NULL;
    if (mp->tx_v.ready) srtp_clear(&mp->tx_v);
    if (mp->rx_v.ready) srtp_clear(&mp->rx_v);
    if (mp->ice) { tri_core_remove_fd(tri_account_core(a), ice_fd(mp->ice)); ice_free(mp->ice); mp->ice = NULL; }
    if (mp->dtls) { dtls_srtp_free(mp->dtls); mp->dtls = NULL; }
    if (mp->media_ready) { srtp_clear(&mp->tx); srtp_clear(&mp->rx); }
    if (mp->dec) { opus_decoder_destroy(mp->dec); mp->dec = NULL; }
    if (mp->play) { tri_audio_close(mp->play); mp->play = NULL; }
    memset(mp, 0, sizeof *mp);
}

static void mesh_capture_gc(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    for (int i = 0; i < MAX_PEERS; i++) if (p->mesh[i].active) return;
    if (p->mesh_capturing) {
        if (!p->media_ready) call_mic_stop(a);
        p->mesh_capturing = 0;
    }
    p->mesh_mic_muted = 0;
    if (p->mesh_enc) { opus_encoder_destroy(p->mesh_enc); p->mesh_enc = NULL; }
    mesh_video_stop(a);
    if (p->mesh_mix_play) { tri_audio_close(p->mesh_mix_play); p->mesh_mix_play = NULL; }
    p->mesh_mix_fill = 0; memset(p->mesh_mix_acc, 0, sizeof p->mesh_mix_acc);
}
static int mesh_start_ice(account_t *a, mesh_peer *mp, int controlling) {
    xp_priv *p = tri_account_priv(a);
    mp->ice = ice_new(controlling);
    if (!mp->ice) return tri_set_error("xmpp: muji ICE socket setup failed");
    ice_set_app_cb(mp->ice, mesh_media_cb, mp);
    tri_core_add_fd(tri_account_core(a), ice_fd(mp->ice), mesh_ice_readable_cb, mp);
    if (p->turn_host[0]) {
        char tip[46], tport[8]; snprintf(tport, sizeof tport, "%d", p->turn_port);
        if (resolve_ipv4(p->turn_host, tport, tip, sizeof tip) == 0)
            ice_set_turn(mp->ice, tip, p->turn_port, p->turn_user, p->turn_pass, "");
    }
    char sip[46]; int sport = 3478;
    if (resolve_stun(sip, sizeof sip, &sport) == 0) ice_gather(mp->ice, sip, sport);
    else ice_gather(mp->ice, NULL, 0);
    snprintf(mp->js.ufrag, sizeof mp->js.ufrag, "%s", ice_ufrag(mp->ice));
    snprintf(mp->js.pwd, sizeof mp->js.pwd, "%s", ice_pwd(mp->ice));
    ice_cands_into(&mp->js, mp->ice, 0);
    mp->ice_sent = ice_candidate_count(mp->ice);
    return 0;
}
static int mesh_start_dtls(account_t *a, mesh_peer *mp, int client, const char *setup) {
    (void)a;
    mp->dtls = dtls_srtp_new(client, mesh_dtls_send, mp);
    if (!mp->dtls) return tri_set_error("xmpp: muji DTLS-SRTP setup failed");
    mp->dtls_started = 0; mp->dtls_secured = 0;
    snprintf(mp->js.setup, sizeof mp->js.setup, "%s", setup);
    snprintf(mp->js.fp_hash, sizeof mp->js.fp_hash, "sha-256");
    snprintf(mp->js.fingerprint, sizeof mp->js.fingerprint, "%s", dtls_srtp_fingerprint(mp->dtls));
    return 0;
}
static void mesh_feed_remote(account_t *a, mesh_peer *mp, const jingle_session *js) {
    (void)a;
    if (!mp->ice) return;
    if (js->ufrag[0]) ice_set_remote_creds(mp->ice, js->ufrag, js->pwd);
    for (int i = 0; i < js->ncand; i++)
        ice_add_remote(mp->ice, js->cand[i].ip, js->cand[i].port, (unsigned)js->cand[i].priority, js->cand[i].type);
}
static void mesh_ice_trickle(account_t *a, mesh_peer *mp) {
    xp_priv *p = tri_account_priv(a);
    if (!mp->ice || ice_candidate_count(mp->ice) <= mp->ice_sent) return;
    jingle_session ti; memset(&ti, 0, sizeof ti);
    snprintf(ti.sid, sizeof ti.sid, "%s", mp->js.sid);
    snprintf(ti.peer, sizeof ti.peer, "%s", mp->full);
    snprintf(ti.content_name, sizeof ti.content_name, "%s", mp->js.content_name[0] ? mp->js.content_name : "audio");
    snprintf(ti.ufrag, sizeof ti.ufrag, "%s", ice_ufrag(mp->ice));
    snprintf(ti.pwd, sizeof ti.pwd, "%s", ice_pwd(mp->ice));
    ice_cands_into(&ti, mp->ice, mp->ice_sent);
    mp->ice_sent = ice_candidate_count(mp->ice);
    char buf[2048], iqid[32]; snprintf(iqid, sizeof iqid, "mjti%u", ++mp->jseq);
    if (jingle_build_transport_info(buf, sizeof buf, p->jid, &ti, iqid)) xs_send(a, buf);
}
static void mesh_ice_pump(account_t *a, mesh_peer *mp) {
    if (!mp->ice) return;
    mesh_ice_trickle(a, mp);
    if (ice_state(mp->ice) == ICE_CONNECTED && !mp->ice_connected) {
        mp->ice_connected = 1;
        char m[360]; snprintf(m, sizeof m, "[muji] path up with %s - securing (DTLS)", mp->full);
        emit(a, TRI_EV_STATUS, mp->room, m);
    }
    if (ice_state(mp->ice) == ICE_CONNECTED && mp->dtls && !mp->dtls_started) {
        mp->dtls_started = 1; dtls_srtp_start(mp->dtls); mesh_dtls_progress(a, mp);
    }
}

static void mesh_offer_video(mesh_peer *mp, const char *codec) {
    const char *cn = strcasecmp(codec, "H264") ? "VP8" : "H264";
    mp->js.vpts[0].id = strcasecmp(cn, "H264") ? 96 : 97;
    snprintf(mp->js.vpts[0].name, sizeof mp->js.vpts[0].name, "%s", cn);
    mp->js.vpts[0].clockrate = 90000; mp->js.vpts[0].channels = 1;
    mp->js.nvpt = 1; mp->js.has_video = 1;
    if (!mp->js.video_name[0]) snprintf(mp->js.video_name, sizeof mp->js.video_name, "1");
    mp->js.vssrc = ((unsigned)rand() << 1) | 1u;
    mp->has_video = 1;
    snprintf(mp->vcodec, sizeof mp->vcodec, "%s", cn);
}
static int mesh_video_active(xp_priv *p) {
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (mp->active && mp->has_video && mp->tx_v.ready && mp->vcodec[0]) return 1;
    }
    return 0;
}
static int mesh_any_active(xp_priv *p) {
    if (p->mesh_capturing) return 1;
    for (int i = 0; i < MAX_PEERS; i++) if (p->mesh[i].active) return 1;
    return 0;
}

static void mesh_video_send(account_t *a, const uint8_t *payload, int plen, int marker, uint32_t ts) {
    xp_priv *p = tri_account_priv(a);
    if (plen <= 0 || plen + 12 + SRTP_AUTH_TAG_LEN > SRTP_MAX_PACKET) return;
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active || !mp->has_video || !mp->tx_v.ready || !mp->vcodec[0]) continue;
        uint8_t rtp[SRTP_MAX_PACKET], prot[SRTP_MAX_PACKET];
        rtp[0] = 0x80; rtp[1] = (uint8_t)(mp->vid_pt | (marker ? 0x80 : 0));
        rtp[2] = (uint8_t)(mp->vseq >> 8); rtp[3] = (uint8_t)mp->vseq; mp->vseq++;
        rtp[4] = (uint8_t)(ts >> 24); rtp[5] = (uint8_t)(ts >> 16); rtp[6] = (uint8_t)(ts >> 8); rtp[7] = (uint8_t)ts;
        rtp[8] = (uint8_t)(mp->vssrc >> 24); rtp[9] = (uint8_t)(mp->vssrc >> 16);
        rtp[10] = (uint8_t)(mp->vssrc >> 8); rtp[11] = (uint8_t)mp->vssrc;
        memcpy(rtp + 12, payload, (size_t)plen);
        int pl = srtp_protect(&mp->tx_v, rtp, 12 + plen, prot);
        if (pl > 0 && mp->ice) ice_send(mp->ice, prot, pl);
    }
}

static void mesh_video_start(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (p->vid_sending) return;
    if (!mesh_video_active(p)) return;
    const char *pick = pick_video_codec();
    if (!pick[0]) { emit(a, TRI_EV_ERROR, NULL, "[muji] no video encoder here (need ffmpeg libvpx or libx264)"); return; }
    snprintf(p->vid_codec, sizeof p->vid_codec, "%s", pick);
    p->vrtp_ts = 0; p->vid_frames = 0;
    int src = p->mesh_video_src ? p->mesh_video_src : 1;
    if (video_spawn_encoder(a, src) != 0) {
        char eb[220]; snprintf(eb, sizeof eb, "[muji] %s", tri_last_error());
        emit(a, TRI_EV_ERROR, NULL, eb); return;
    }
    p->vid_sending = 1;
    p->vtx_prev_on = (src != 2);
    emit(a, TRI_EV_STATUS, NULL, src == 2 ? "[muji] screensharing to the room" : "[muji] sending video to the room");
}
static void mesh_video_stop(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    p->mesh_video_src = 0;
    if (p->vid_sending && !p->ice) call_video_stop(a);
}

static void mesh_video_rx_feed(account_t *a, mesh_peer *mp, const uint8_t *data, int len) {
    if (!mp->rx_v.ready) return;
    uint8_t rtp[SRTP_MAX_PACKET];
    int rl = srtp_unprotect(&mp->rx_v, data, len, rtp);
    if (rl < 12) return;
    int hl = srtp_rtp_header_len(rtp, rl);
    if (rl <= hl) return;
    int marker = rtp[1] & 0x80;
    mp->vrx_peer_ssrc = ((uint32_t)rtp[8] << 24) | ((uint32_t)rtp[9] << 16) | ((uint32_t)rtp[10] << 8) | rtp[11];
    uint16_t seq = (uint16_t)((rtp[2] << 8) | rtp[3]);
    if (mp->vrx_have_seq && seq != (uint16_t)(mp->vrx_last_seq + 1)) {
        if (mp->vrx_vp8)  { mp->vrx_vp8->in_frame = 0; mp->vrx_vp8->len = 0; }
        if (mp->vrx_h264) { mp->vrx_h264->active = 0; mp->vrx_h264->len = 0; }
        mp->vrx_want_key = 1;
    }
    mp->vrx_last_seq = seq; mp->vrx_have_seq = 1;
    const uint8_t *pl = rtp + hl; int plen = rl - hl;
    const char *codec = (mp->js.nvpt > 0) ? mp->js.vpts[0].name : "VP8";
    if (!strcasecmp(codec, "H264")) {
        if (!mp->vrx_h264) { mp->vrx_h264 = calloc(1, sizeof *mp->vrx_h264); if (!mp->vrx_h264) return; h264_depkt_reset(mp->vrx_h264); }
        static uint8_t out[H264_BUF];
        int wrote = h264_depacketize(mp->vrx_h264, pl, plen, out, (int)sizeof out);
        if (wrote > 0 && !vdec_try(a, &mp->vdec, &mp->vdec_tried, mp->vwhich, "H264", out, wrote))
            vsink_h264(&mp->vrx, a, mp->vwhich, out, wrote);
    } else {
        if (!mp->vrx_vp8) { mp->vrx_vp8 = calloc(1, sizeof *mp->vrx_vp8); if (!mp->vrx_vp8) return; }
        const uint8_t *frame; int flen;
        if (vp8_depacketize(mp->vrx_vp8, pl, plen, marker, &frame, &flen) &&
            !vdec_try(a, &mp->vdec, &mp->vdec_tried, mp->vwhich, "VP8", frame, flen))
            vsink_vp8(&mp->vrx, a, mp->vwhich, frame, flen);
    }
}

static void mesh_send_pli(account_t *a, mesh_peer *mp) {
    (void)a;
    if (!mp->ice || !mp->tx.ready || !mp->vrx_peer_ssrc) return;
    double t = now_s();
    if (t - mp->vrx_pli_last < 0.5) return;
    mp->vrx_pli_last = t;
    uint32_t me = mp->vssrc ? mp->vssrc : mp->rtp_ssrc;
    uint8_t pli[12] = { 0x81, 206, 0, 2,
        (uint8_t)(me >> 24), (uint8_t)(me >> 16), (uint8_t)(me >> 8), (uint8_t)me,
        (uint8_t)(mp->vrx_peer_ssrc >> 24), (uint8_t)(mp->vrx_peer_ssrc >> 16),
        (uint8_t)(mp->vrx_peer_ssrc >> 8), (uint8_t)mp->vrx_peer_ssrc };
    uint8_t prot[SRTP_MAX_PACKET];
    int pl = srtcp_protect(&mp->tx, pli, 12, prot);
    if (pl > 0) ice_send(mp->ice, prot, pl);
}

static int mesh_do_initiate(account_t *a, const char *room, const char *full) {
    xp_priv *p = tri_account_priv(a);
    mesh_peer *mp = mesh_alloc(a, room, full);
    if (!mp) return tri_set_error("xmpp: muji mesh full (max %d peers)", MAX_PEERS);
    memset(&mp->js, 0, sizeof mp->js);
    snprintf(mp->js.peer, sizeof mp->js.peer, "%s", full);
    snprintf(mp->js.sid, sizeof mp->js.sid, "mj%u-%ld", ++mp->jseq, (long)now_s());
    snprintf(mp->js.content_name, sizeof mp->js.content_name, "audio");
    mp->js.pts[0] = (jingle_payload){ 111, "opus", 48000, 2 }; mp->js.npt = 1;
    mp->js.ssrc = (unsigned)rand() | 1u; snprintf(mp->js.cname, sizeof mp->js.cname, "trichat%u", mp->js.ssrc);
    {
        const char *pick = pick_video_codec();
        if (pick[0]) mesh_offer_video(mp, pick);
    }
    if (mesh_start_ice(a, mp, 1) != 0) { mesh_free_peer(a, mp); return -1; }
    if (mesh_start_dtls(a, mp, 0, "actpass") != 0) { mesh_free_peer(a, mp); return -1; }
    mp->js.state = JINGLE_OUTGOING;
    char iqid[32]; snprintf(iqid, sizeof iqid, "mjin%u", ++mp->jseq);
    char buf[4096];
    if (!jingle_build_initiate(buf, sizeof buf, p->jid, &mp->js, iqid)) { mesh_free_peer(a, mp); return tri_set_error("xmpp: muji initiate too large"); }
    if (xs_send(a, buf) != 0) { mesh_free_peer(a, mp); return -1; }
    char m[360]; snprintf(m, sizeof m, "[muji] calling %s", full);
    emit(a, TRI_EV_STATUS, room, m);
    return 0;
}

static int mesh_do_accept(account_t *a, mesh_peer *mp) {
    xp_priv *p = tri_account_priv(a);
    if (!mp->ice) return tri_set_error("xmpp: muji leg has no ICE agent");
    int opi = -1;
    for (int i = 0; i < mp->js.npt; i++) if (!strcasecmp(mp->js.pts[i].name, "opus")) { opi = i; break; }
    if (opi >= 0) mp->js.pts[0] = mp->js.pts[opi];
    else          mp->js.pts[0] = (jingle_payload){ 111, "opus", 48000, 2 };
    mp->js.npt = 1;
    mp->js.ssrc = (unsigned)rand() | 1u; snprintf(mp->js.cname, sizeof mp->js.cname, "trichat%u", mp->js.ssrc);
    if (mp->has_video && mp->js.nvpt > 0) {
        mp->js.nvpt = 1; mp->js.has_video = 1;
        mp->js.vssrc = ((unsigned)rand() << 1) | 1u;
        if (!mp->js.video_name[0]) snprintf(mp->js.video_name, sizeof mp->js.video_name, "1");
    } else { mp->js.has_video = 0; mp->js.nvpt = 0; }
    mp->js.state = JINGLE_ACTIVE;
    char iqid[32]; snprintf(iqid, sizeof iqid, "mjac%u", ++mp->jseq);
    char buf[4096];
    if (!jingle_build_accept(buf, sizeof buf, p->jid, &mp->js, iqid)) return tri_set_error("xmpp: muji accept too large");
    if (xs_send(a, buf) != 0) return -1;
    ice_start_checks(mp->ice);
    mesh_ice_pump(a, mp);
    return 0;
}

static void mesh_maybe_initiate(account_t *a, const char *room, const char *peer_nick) {
    xp_priv *p = tri_account_priv(a);
    struct muji_state *m = NULL;
    for (int i = 0; i < MAX_MUJI_CALLS; i++) if (!strcmp(p->muji[i].room, room)) { m = &p->muji[i]; break; }
    if (!m || !m->active) return;
    const char *self = tri_channel_nick(a, room); if (!self[0]) self = p->node;
    char ourfull[320], peerfull[320];
    snprintf(ourfull, sizeof ourfull, "%s/%s", room, self);
    snprintf(peerfull, sizeof peerfull, "%s/%s", room, peer_nick);
    if (mesh_find(p, peerfull)) return;
    if (strcmp(ourfull, peerfull) >= 0) return;
    if (mesh_do_initiate(a, room, peerfull) != 0) emit(a, TRI_EV_ERROR, room, tri_last_error());
}
static void mesh_end_peer_full(account_t *a, const char *full) {
    xp_priv *p = tri_account_priv(a);
    mesh_peer *mp = mesh_find(p, full);
    if (!mp) return;
    if (mp->js.state != JINGLE_ENDED && mp->js.sid[0]) {
        char iqid[32]; snprintf(iqid, sizeof iqid, "mjtm%u", ++mp->jseq);
        char buf[512]; if (jingle_build_terminate(buf, sizeof buf, p->jid, &mp->js, "success", iqid)) xs_send(a, buf);
    }
    mesh_free_peer(a, mp);
    mesh_capture_gc(a);
}
static void mesh_end_room(account_t *a, const char *room) {
    xp_priv *p = tri_account_priv(a);
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active || strcmp(mp->room, room)) continue;
        if (mp->js.state != JINGLE_ENDED && mp->js.sid[0]) {
            char iqid[32]; snprintf(iqid, sizeof iqid, "mjtm%u", ++mp->jseq);
            char buf[512]; if (jingle_build_terminate(buf, sizeof buf, p->jid, &mp->js, "success", iqid)) xs_send(a, buf);
        }
        mesh_free_peer(a, mp);
    }
    mesh_capture_gc(a);
}
static void mesh_teardown_all(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    mesh_video_stop(a);
    for (int i = 0; i < MAX_PEERS; i++) if (p->mesh[i].active) mesh_free_peer(a, &p->mesh[i]);
    if (p->mesh_enc) { opus_encoder_destroy(p->mesh_enc); p->mesh_enc = NULL; }
    if (p->mesh_mix_play) { tri_audio_close(p->mesh_mix_play); p->mesh_mix_play = NULL; }
    p->mesh_capturing = 0;
}

static int mesh_route_jingle(account_t *a, const char *from, const jingle_session *jsp, const char *action) {
    xp_priv *p = tri_account_priv(a);
    char barefrom[256]; bare_jid(from, barefrom, sizeof barefrom);
    struct muji_state *m = NULL;
    for (int i = 0; i < MAX_MUJI_CALLS; i++) if (!strcmp(p->muji[i].room, barefrom)) { m = &p->muji[i]; break; }
    if (!m || !m->active) {
        if (is_groupchat_target(p, barefrom) && !strcmp(action, "session-initiate")) {
            jingle_session d = *jsp; snprintf(d.peer, sizeof d.peer, "%s", from);
            char tb[512]; if (jingle_build_terminate(tb, sizeof tb, p->jid, &d, "decline", "mjdec")) xs_send(a, tb);
            return 1;
        }
        return 0;
    }

    jingle_session js = *jsp;
    if (!strcmp(action, "session-initiate")) {
        mesh_peer *mp = mesh_alloc(a, barefrom, from);
        if (!mp) return 1;
        mp->js = js; snprintf(mp->js.peer, sizeof mp->js.peer, "%s", from);
        if (js.has_video && js.nvpt > 0 && can_encode_codec(js.vpts[0].name)) {
            mp->has_video = 1;
            snprintf(mp->vcodec, sizeof mp->vcodec, "%s", strcasecmp(js.vpts[0].name, "H264") ? "VP8" : "H264");
        } else { mp->js.has_video = 0; mp->js.nvpt = 0; }
        jingle_session peer = js;
        if (mesh_start_ice(a, mp, 0) == 0) {
            mesh_feed_remote(a, mp, &peer);
            mesh_start_dtls(a, mp, 1, "active");
            if (mp->dtls && peer.fingerprint[0]) dtls_srtp_set_peer_fingerprint(mp->dtls, peer.fingerprint);
        }
        mp->js.state = JINGLE_INCOMING;
        mesh_do_accept(a, mp);
        return 1;
    }
    mesh_peer *mp = mesh_find(p, from);
    if (!mp || strcmp(mp->js.sid, js.sid)) return 1;
    if (!strcmp(action, "session-accept")) {
        if (mp->js.state == JINGLE_OUTGOING) {
            mp->js.state = JINGLE_ACTIVE;
            memcpy(mp->js.pts, js.pts, sizeof js.pts); mp->js.npt = js.npt;
            if (js.has_video && js.nvpt > 0) {
                mp->js.vpts[0] = js.vpts[0]; mp->js.nvpt = 1; mp->has_video = 1;
                snprintf(mp->vcodec, sizeof mp->vcodec, "%s", strcasecmp(js.vpts[0].name, "H264") ? "VP8" : "H264");
            } else { mp->has_video = 0; mp->js.has_video = 0; mp->js.nvpt = 0; }
            mesh_feed_remote(a, mp, &js);
            if (mp->dtls && js.fingerprint[0]) dtls_srtp_set_peer_fingerprint(mp->dtls, js.fingerprint);
            if (mp->ice) ice_start_checks(mp->ice);
            mesh_ice_pump(a, mp);
        }
    } else if (!strcmp(action, "session-terminate")) {
        char left[360]; snprintf(left, sizeof left, "[muji] %s left the call", mp->full);
        mesh_free_peer(a, mp); mesh_capture_gc(a);
        emit(a, TRI_EV_STATUS, barefrom, left);
    } else if (!strcmp(action, "transport-info")) {
        mesh_feed_remote(a, mp, &js); mesh_ice_pump(a, mp);
    }
    return 1;
}
static void mesh_tick(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    double t = now_s();
    int any = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        mesh_peer *mp = &p->mesh[i];
        if (!mp->active) continue;
        any = 1;
        if (mp->ice) { ice_tick(mp->ice, t); mesh_ice_pump(a, mp); }
        if (mp->dtls && mp->dtls_started) { dtls_srtp_tick(mp->dtls); mesh_dtls_progress(a, mp); }
        if (mp->vrx_want_key) { mp->vrx_want_key = 0; mesh_send_pli(a, mp); }
    }
    if (any && p->mesh_mixed) mesh_mix_flush(a);
}
#endif

static int wav_u32le(const uint8_t *b) { return b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24; }
static int load_wav48(const char *path, int16_t **out, size_t *out_n) {
    FILE *f = fopen(path, "rb");
    if (!f) return tri_set_error("xmpp: cannot open '%s': %s", path, strerror(errno));
    uint8_t hdr[12];
    if (fread(hdr, 1, 12, f) != 12 || memcmp(hdr, "RIFF", 4) || memcmp(hdr + 8, "WAVE", 4))
        { fclose(f); return tri_set_error("xmpp: '%s' is not a WAV file", path); }
    int chans = 0, rate = 0, bits = 0; uint8_t ch[8];
    while (fread(ch, 1, 8, f) == 8) {
        uint32_t sz = wav_u32le(ch + 4);
        if (!memcmp(ch, "fmt ", 4)) {
            uint8_t fmt[16]; if (fread(fmt, 1, 16, f) != 16) break;
            chans = fmt[2] | fmt[3] << 8; rate = wav_u32le(fmt + 4); bits = fmt[14] | fmt[15] << 8;
            if (sz > 16) fseek(f, sz - 16, SEEK_CUR);
        } else if (!memcmp(ch, "data", 4)) {
            if (chans != 1 || rate != 48000 || bits != 16) {
                fclose(f);
                return tri_set_error("xmpp: '%s' must be 48000Hz mono 16-bit (got %dHz, %dch, %d-bit) - convert with: ffmpeg -i in -ar 48000 -ac 1 -c:a pcm_s16le out.wav", path, rate, chans, bits);
            }
            int16_t *pcm = malloc(sz); if (!pcm) { fclose(f); return tri_set_error("xmpp: out of memory for '%s'", path); }
            size_t got = fread(pcm, 1, sz, f); fclose(f);
            *out = pcm; *out_n = got / 2; return 0;
        } else fseek(f, sz, SEEK_CUR);
    }
    fclose(f);
    return tri_set_error("xmpp: '%s' has no data chunk", path);
}
static int xmpp_play(account_t *a, const char *path) {
    xp_priv *p = tri_account_priv(a);
    if (!p || !p->media_ready) return tri_set_error("xmpp: no active call - soundboard needs a live call");
    int16_t *pcm = NULL; size_t pcm_n = 0;
    if (load_wav48(path, &pcm, &pcm_n) != 0) return -1;
    free(p->sb_pcm);
    p->sb_pcm = pcm; p->sb_n = pcm_n; p->sb_pos = 0; p->sb_start = now_s(); p->sb_playing = 1;
    char m[160]; snprintf(m, sizeof m, "[call] soundboard: playing %s (%.1fs)", path, (double)pcm_n / 48000.0);
    emit(a, TRI_EV_STATUS, p->call.peer, m);
    return 0;
}

static int xmpp_mic(account_t *a, int on) {
    xp_priv *p = tri_account_priv(a);
    if (!p) return tri_set_error("xmpp: not connected");
#ifdef TRI_MUJI_MESH
    if (!p->media_ready && mesh_any_active(p)) {
        p->mesh_mic_muted = !on;
        if (on) mesh_ensure_capture(a); else call_mic_stop(a);
        emit(a, TRI_EV_STATUS, NULL, on ? "[muji] mic on" : "[muji] mic muted");
        return 0;
    }
#endif
    if (!p->media_ready) return tri_set_error("xmpp: no active call");
    if (on) call_mic_start(a); else call_mic_stop(a);
    emit(a, TRI_EV_STATUS, p->call.peer, on ? "[call] mic on" : "[call] mic muted");
    return 0;
}

static int xmpp_call(account_t *a, const char *target, int action) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE || !p->jid[0]) return tri_set_error("xmpp: not connected");

    if (is_groupchat_target(p, target)) return muji_call(a, target, action);

    if (action == TRI_CALL_VIDEO_STOP) {
        if (!p->vid_sending) return tri_set_error("xmpp: not sending video");
        call_video_stop(a); p->want_video = 0;
        emit(a, TRI_EV_STATUS, p->call.peer, "[call] video stopped");
        return 0;
    }
    if (action == TRI_CALL_VIDEO || action == TRI_CALL_SCREENSHARE) {
        int src = (action == TRI_CALL_SCREENSHARE) ? 2 : 1;
        if (p->media_ready && p->call.has_video) {
            p->want_video = src;
            call_video_start(a, src);
            return 0;
        }
        if (p->media_ready || p->call.state != JINGLE_ENDED)
            return tri_set_error("xmpp: this call has no video stream - hang up, then place a %s call",
                                 src == 2 ? "screenshare" : "video");
        p->want_video = src;
        action = TRI_CALL_START;
    }

    if (action == TRI_CALL_START) {
        if (p->want_video && !pick_video_codec()[0]) {
            p->want_video = 0;
            return tri_set_error("xmpp: no video encoder here (install ffmpeg with libvpx or libx264) - voice calls still work");
        }

        char barepeer[256]; bare_jid(target, barepeer, sizeof barepeer);
        snprintf(p->jmi_id, sizeof p->jmi_id, "tc%u-%ld", ++p->jingle_seq, (long)now_s());
        snprintf(p->jmi_peer, sizeof p->jmi_peer, "%s", barepeer);
        p->jmi_out = 1; p->jmi_in = 0;
        char pesc[300]; xml_escape(barepeer, pesc, sizeof pesc);
        const char *vdesc = p->want_video ? "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='video'/>" : "";
        xs_sendf(a, "<message to='%s'><propose xmlns='urn:xmpp:jingle-message:0' id='%s'>"
                    "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/>%s</propose>"
                    "<store xmlns='urn:xmpp:hints'/></message>", pesc, p->jmi_id, vdesc);
        char m[300]; snprintf(m, sizeof m, "[call] %s %s...", p->want_video ? (p->want_video == 2 ? "screensharing to" : "video-calling") : "calling", barepeer);
        emit(a, TRI_EV_STATUS, barepeer, m);
        call_signal(a, "ringing", barepeer, p->want_video != 0);
        return 0;
    }
    if (action == TRI_CALL_ACCEPT) {
        if (p->jmi_in && p->jmi_peer[0]) {
            char pesc[300]; xml_escape(p->jmi_peer, pesc, sizeof pesc);
            xs_sendf(a, "<message to='%s'><proceed xmlns='urn:xmpp:jingle-message:0' id='%s'/></message>", pesc, p->jmi_id);
            p->jmi_in = 0; p->auto_accept = 1;
            char pb[256]; bare_jid(p->jmi_peer, pb, sizeof pb);
            char m[300]; snprintf(m, sizeof m, "[call] answering %s...", pb); emit(a, TRI_EV_STATUS, pb, m);
            return 0;
        }
        if (p->call.state == JINGLE_INCOMING) return call_do_accept(a);
        return tri_set_error("xmpp: no incoming call to accept");
    }
    if (action == TRI_CALL_HANGUP) {
        char pesc[300];
        if (p->jmi_out && p->jmi_peer[0]) {
            xml_escape(p->jmi_peer, pesc, sizeof pesc);
            xs_sendf(a, "<message to='%s'><retract xmlns='urn:xmpp:jingle-message:0' id='%s'/></message>", pesc, p->jmi_id);
        } else if (p->jmi_in && p->jmi_peer[0]) {
            xml_escape(p->jmi_peer, pesc, sizeof pesc);
            xs_sendf(a, "<message to='%s'><reject xmlns='urn:xmpp:jingle-message:0' id='%s'/></message>", pesc, p->jmi_id);
        } else if (p->call.state != JINGLE_ENDED) {
            const char *reason = p->call.state == JINGLE_INCOMING ? "decline" : "success";
            char iqid[32]; snprintf(iqid, sizeof iqid, "jgtm%u", ++p->jingle_seq);
            char buf[512];
            if (jingle_build_terminate(buf, sizeof buf, p->jid, &p->call, reason, iqid)) xs_send(a, buf);
        } else {
            return tri_set_error("xmpp: no active call");
        }
        char pb[256]; bare_jid(p->jmi_peer[0] ? p->jmi_peer : p->call.peer, pb, sizeof pb);
        char m[300]; snprintf(m, sizeof m, "[call] call with %s ended", pb); emit(a, TRI_EV_STATUS, pb, m);
        call_signal(a, "ended", pb, 0);
        call_end_ice(a);
        memset(&p->call, 0, sizeof p->call);
        p->jmi_in = p->jmi_out = p->auto_accept = 0; p->jmi_id[0] = 0;
        return 0;
    }
    return tri_set_error("xmpp: unknown call action");
}

static void xmpp_join(account_t *a, const char *target) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) { if (p) snprintf(p->autojoin, sizeof p->autojoin, "%s", target); return; }
    if (is_groupchat_target(p, target)) { do_muc_join(a, target); return; }
    if (strchr(target, '/')) { emit(a, TRI_EV_STATUS, target, "chat ready"); return; }
    if (p->npj >= 8) { do_muc_join(a, target); publish_bookmark(a, target); return; }
    static unsigned jc = 0;
    int k = p->npj++;
    snprintf(p->pj[k].id, sizeof p->pj[k].id, "jchk%u", ++jc);
    snprintf(p->pj[k].target, sizeof p->pj[k].target, "%s", target);
    char tesc[300]; xml_escape(target, tesc, sizeof tesc);
    xs_sendf(a, "<iq type='get' id='%s' to='%s'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>", p->pj[k].id, tesc);
}

static void xmpp_leave(account_t *a, const char *target) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return;
    int was_room = is_groupchat_target(p, target);
    for (int i = 0; i < p->nrooms; i++)
        if (!strcmp(p->rooms[i], target)) { for (int j = i; j < p->nrooms - 1; j++) snprintf(p->rooms[j], 256, "%s", p->rooms[j + 1]); p->nrooms--; break; }
    if (!was_room) return;
    xs_sendf(a, "<presence to='%s/%s' type='unavailable'/>", target, p->node);
    retract_bookmark(a, target);
}

static void xmpp_tick(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return;
    double t = now_s();
    if (t - p->last_ka >= 30.0) { xs_send(a, " "); p->last_ka = t; }
    if (p->nrooms && t - p->last_selfping >= 60.0) {
        p->last_selfping = t;
        for (int i = 0; i < p->nrooms; i++) {
            const char *nick = tri_channel_nick(a, p->rooms[i]); if (!nick[0]) nick = p->node;
            char rn[300], nk[160]; xml_escape(p->rooms[i], rn, sizeof rn); xml_escape(nick, nk, sizeof nk);
            xs_sendf(a, "<iq type='get' id='sp:%d' to='%s/%s'><ping xmlns='urn:xmpp:ping'/></iq>", i, rn, nk);
        }
    }
    if (p->ice) { ice_tick(p->ice, t); ice_pump(a); }
#ifdef TRI_MUJI_MESH
    mesh_tick(a);
#endif
    if (p->dtls && p->dtls_started) { dtls_srtp_tick(p->dtls); call_dtls_progress(a); }
    if (p->ice && p->dtls_started && !p->dtls_secured && t - p->dtls_dbg_last >= 2.0) {
        char dbg[1024]; ice_debug(p->ice, dbg, sizeof dbg);
        tri_log(tri_account_core(a), "dtls securing: %s", dbg);
        p->dtls_dbg_last = t;
    }
    if (p->media_ready && t - p->media_dbg_last >= 3.0) {
        tri_log(tri_account_core(a), "media rx: pkts=%d authfail=%d decoded=%d decfail=%d play=%s",
                p->rx_pkts, p->rx_authfail, p->rx_decoded, p->rx_decfail, p->play ? "open" : "NULL");
        p->media_dbg_last = t;
    }
    if (p->vid_sending) screen_grab_pump(a);
    if (p->pace_q) pace_drain(a);
    if (p->vrx.in_fd > 0) vsink_flush(&p->vrx, tri_account_core(a));
    if (p->vtx_prev.in_fd > 0) vsink_flush(&p->vtx_prev, tri_account_core(a));
    if (p->vrx_want_key) { p->vrx_want_key = 0; video_send_pli(a); }
    if (p->vid_sending && t - p->vid_dbg_last >= 3.0) {
        tri_log(tri_account_core(a), "video tx: frames=%d pt=%d ssrc=%u q=%d drop=%d%s",
                p->vid_frames, p->vid_pt, p->vrtp_ssrc, p->pace_count, p->pace_dropped,
                p->vid_frames == 0 ? " (no frames yet - encoder/capture may be failing)" : "");
        p->vid_dbg_last = t;
    }

    if (p->media_ready && p->sb_playing) {
        size_t due = (size_t)((t - p->sb_start) / 0.02);
        size_t sent = p->sb_pos / 960;
        while (p->sb_playing && sent < due && p->sb_pos < p->sb_n) {
            int16_t frame[960]; size_t avail = p->sb_n - p->sb_pos;
            size_t cnt = avail < 960 ? avail : 960;
            memcpy(frame, p->sb_pcm + p->sb_pos, cnt * 2);
            if (cnt < 960) memset(frame + cnt, 0, (960 - cnt) * 2);
            xmpp_send_audio(a, frame, 960);
            p->sb_pos += 960; sent++;
        }
        if (p->sb_pos >= p->sb_n) { free(p->sb_pcm); p->sb_pcm = NULL; p->sb_n = p->sb_pos = 0; p->sb_playing = 0; }
    }

    if (p->media_ready && !p->mic && !p->sb_playing && t - p->last_media >= 0.02) {
        static const int16_t silence[960] = { 0 };
        xmpp_send_audio(a, silence, 960);
        p->last_media = t;
    }

    const char *ft = tri_account_faketyping(a);
    if (ft[0] && t - p->last_faketype >= 12.0) { xmpp_typing(a, ft, 1); p->last_faketype = t; }

    for (int i = 0; i < (int)(sizeof p->opend / sizeof p->opend[0]); i++)
        if (p->opend[i].active && t - p->opend[i].started > 15.0) omemo_finalize_send(a, &p->opend[i]);

    if (p->omemo && t - p->omemo_last_flush >= 4.0) { omemo_store_flush(p->omemo); p->omemo_last_flush = t; }
}

static const char *guess_ctype(const char *path) {
    const char *d = strrchr(path, '.'); if (!d) return "application/octet-stream";
    if (!strcasecmp(d, ".png")) return "image/png";
    if (!strcasecmp(d, ".jpg") || !strcasecmp(d, ".jpeg")) return "image/jpeg";
    if (!strcasecmp(d, ".gif")) return "image/gif";
    if (!strcasecmp(d, ".webp")) return "image/webp";
    if (!strcasecmp(d, ".bmp")) return "image/bmp";
    if (!strcasecmp(d, ".pdf")) return "application/pdf";
    if (!strcasecmp(d, ".txt")) return "text/plain";
    if (!strcasecmp(d, ".mp4")) return "video/mp4";
    if (!strcasecmp(d, ".webm")) return "video/webm";
    if (!strcasecmp(d, ".mp3")) return "audio/mpeg";
    if (!strcasecmp(d, ".ogg")) return "audio/ogg";
    return "application/octet-stream";
}

static void up_emit(account_t *a, xup_t *ctx, tri_event_kind k, const char *text) {
    if (ctx->deliver_key[0]) {
        tri_event_t ev = { k, ctx->deliver_key, ctx->deliver_target, text, NULL, 0 };
        tri_emit(tri_account_core(a), &ev);
    } else emit(a, k, ctx->target, text);
}

static void xmpp_put_done(void *ud, int ok, int status, const char *body, size_t len, const char *ctype) {
    (void)body; (void)len; (void)ctype;
    xup_t *ctx = ud;

    int relay = ctx->deliver_key[0] != 0;
    const char *dkey = relay ? ctx->deliver_key : ctx->acctkey;
    const char *dtgt = relay ? ctx->deliver_target : ctx->target;
    account_t *dst = tri_account_find_by_key(ctx->core, dkey);
    if (ok && (status == 200 || status == 201)) {
        if (dst) {
            tri_send(dst, dtgt, ctx->geturl);

            if (relay) { tri_event_t se = { TRI_EV_MESSAGE, dkey, dtgt, ctx->geturl, "you", 0, 0, 0, NULL };
                         tri_emit(ctx->core, &se); }
        }
    } else { char m[128]; snprintf(m, sizeof m, "upload failed (HTTP %d)", status);
             tri_event_t ev = { TRI_EV_ERROR, dkey, dtgt, m, NULL, 0 }; tri_emit(ctx->core, &ev); }
    free(ctx->data); free(ctx);
}

static int xup_start(account_t *a, const char *target, const char *path, const char *dkey, const char *dtgt) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("xmpp: not connected - can't upload");
    if (!p->upload_service[0]) return tri_set_error("xmpp: this server offers no HTTP file upload (XEP-0363)");
    if (p->npend >= MAX_UPLOADS) return tri_set_error("xmpp: too many uploads already in flight");
    FILE *f = fopen(path, "rb");
    if (!f) return tri_set_error("xmpp: cannot open '%s': %s", path, strerror(errno));
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return tri_set_error("xmpp: '%s' is empty or unreadable", path); }
    if (sz > 100L * 1024 * 1024) { fclose(f); return tri_set_error("xmpp: '%s' is larger than 100 MB", path); }
    unsigned char *data = malloc((size_t)sz);
    if (!data) { fclose(f); return tri_set_error("xmpp: out of memory"); }
    if (fread(data, 1, (size_t)sz, f) != (size_t)sz) { free(data); fclose(f); return tri_set_error("xmpp: read error on '%s'", path); }
    fclose(f);
    xup_t *ctx = calloc(1, sizeof *ctx);
    if (!ctx) { free(data); return tri_set_error("xmpp: out of memory"); }
    ctx->core = tri_account_core(a);
    snprintf(ctx->acctkey, sizeof ctx->acctkey, "%s", tri_account_key(a));
    snprintf(ctx->target, sizeof ctx->target, "%s", target);
    if (dkey && dkey[0]) { snprintf(ctx->deliver_key, sizeof ctx->deliver_key, "%s", dkey);
                           snprintf(ctx->deliver_target, sizeof ctx->deliver_target, "%s", dtgt ? dtgt : ""); }
    snprintf(ctx->ctype, sizeof ctx->ctype, "%s", guess_ctype(path));
    ctx->data = data; ctx->len = (size_t)sz;
    static int upc = 0; snprintf(ctx->id, sizeof ctx->id, "up%d", ++upc);
    p->pend[p->npend++] = ctx;
    const char *base = strrchr(path, '/'); base = base ? base + 1 : path;
    char fesc[256]; xml_escape(base, fesc, sizeof fesc);
    const char *ns = p->upload_ns[0] ? p->upload_ns : "urn:xmpp:http:upload:0";
    xs_sendf(a, "<iq type='get' id='%s' to='%s'><request xmlns='%s' filename='%s' size='%zu' content-type='%s'/></iq>",
             ctx->id, p->upload_service, ns, fesc, ctx->len, ctx->ctype);
    up_emit(a, ctx, TRI_EV_STATUS, "uploading...");
    return 0;
}

static int xmpp_upload(account_t *a, const char *target, const char *path) {
    return xup_start(a, target, path, "", "");
}

static int xmpp_upload_relay(account_t *via, const char *path, const char *deliver_key, const char *deliver_target) {
    return xup_start(via, deliver_target, path, deliver_key, deliver_target);
}

static int xmpp_upload_ready(account_t *a) {
    xp_priv *p = tri_account_priv(a);
    return p && p->state == ST_ONLINE && p->upload_service[0] != 0;
}

static int xmpp_moderate(account_t *a, const char *room, const char *user, const char *action, const char *arg) {
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("xmpp: not connected");
    if (!room || !room[0]) return tri_set_error("xmpp: moderation needs a room");
    char rn[300], nk[160]; xml_escape(room, rn, sizeof rn); xml_escape(user ? user : "", nk, sizeof nk);
    const char *role = NULL;
    if      (!strcmp(action, "kick"))    role = "none";
    else if (!strcmp(action, "mute") || !strcmp(action, "devoice"))   role = "visitor";
    else if (!strcmp(action, "unmute") || !strcmp(action, "voice"))   role = "participant";
    else if (!strcmp(action, "op"))      role = "moderator";
    else if (!strcmp(action, "deop"))    role = "participant";
    else if (!strcmp(action, "ban") || !strcmp(action, "unban") ||
             !strcmp(action, "member") || !strcmp(action, "admin") || !strcmp(action, "owner")) {
        if (!arg || !arg[0]) return tri_set_error("xmpp: %s needs the user's real JID", action);
        const char *aff = !strcmp(action, "ban") ? "outcast" : !strcmp(action, "unban") ? "none" : action;
        char jid[300]; xml_escape(arg, jid, sizeof jid);
        return xs_sendf(a, "<iq type='set' id='mod1' to='%s'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                           "<item affiliation='%s' jid='%s'/></query></iq>", rn, aff, jid);
    } else if (!strcmp(action, "afflist")) {
        static const char *affs[] = { "owner", "admin", "member", "outcast" };
        emit(a, TRI_EV_STATUS, room, "- room affiliations -");
        for (int i = 0; i < 4; i++)
            xs_sendf(a, "<iq type='get' id='afl' to='%s'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                        "<item affiliation='%s'/></query></iq>", rn, affs[i]);
        return 0;
    } else return tri_set_error("xmpp: unsupported moderation action '%s'", action);
    return xs_sendf(a, "<iq type='set' id='mod1' to='%s'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                       "<item nick='%s' role='%s'/></query></iq>", rn, nk, role);
}

static int xmpp_user_info(account_t *a, const char *channel, const char *user) {
    (void)channel;
    xp_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("xmpp: not connected");
    if (!user || !user[0]) return tri_set_error("xmpp: no user to look up");
    char esc[300]; xml_escape(user, esc, sizeof esc);
    return xs_sendf(a, "<iq type='get' id='vc1' to='%s'><vCard xmlns='vcard-temp'/></iq>", esc);
}

const protocol_backend_t backend_xmpp = {
    .name = "xmpp",
    .connect = xmpp_connect,
    .disconnect = xmpp_disconnect,
    .send_message = xmpp_send,
    .join = xmpp_join,
    .leave = xmpp_leave,
    .on_socket_readable = xmpp_on_readable,
    .on_socket_writable = xmpp_on_writable,
    .tick = xmpp_tick,
    .play_file = xmpp_play,
    .mic = xmpp_mic,
    .upload = xmpp_upload,
    .upload_relay = xmpp_upload_relay,
    .upload_ready = xmpp_upload_ready,
    .react = xmpp_react,
    .correct = xmpp_correct,
    .moderate = xmpp_moderate,
    .user_info = xmpp_user_info,
    .is_group = xmpp_is_group,
    .typing = xmpp_typing,
    .call = xmpp_call,
    .call_peers = muji_call_peers,
    .call_peer_mute = muji_call_peer_mute,
    .omemo_own_fingerprint = xmpp_omemo_own_fingerprint,
    .omemo_devices = xmpp_omemo_devices,
    .omemo_set_trust = xmpp_omemo_set_trust,
};
