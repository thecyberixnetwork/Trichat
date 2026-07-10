#include "jingle.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int attr(const char *elem, const char *name, char *out, size_t osz) {
    const char *gt = strchr(elem, '>');
    char needle[40]; snprintf(needle, sizeof needle, "%s=", name);
    const char *q = elem;
    while ((q = strstr(q, needle))) {
        if (gt && q > gt) break;
        if (q == elem || q[-1] == ' ' || q[-1] == '\t') {
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
    out[0] = '\0';
    return 0;
}
static int attr_int(const char *elem, const char *name) {
    char buf[24]; return attr(elem, name, buf, sizeof buf) ? atoi(buf) : 0;
}

static const char *next_elem(const char **cur, const char *open) {
    size_t ol = strlen(open);
    const char *t = *cur;
    while ((t = strstr(t, open))) {
        char n = t[ol];
        if (n == ' ' || n == '\t' || n == '>' || n == '/' || n == '\n' || n == '\r') { *cur = t + ol; return t; }
        t += ol;
    }
    return NULL;
}

int jingle_parse(const char *stanza, jingle_session *s, char *action, size_t action_sz) {
    if (action && action_sz) action[0] = '\0';
    const char *j = strstr(stanza, "<jingle");
    if (!j) return 0;
    memset(s, 0, sizeof *s);

    if (action) attr(j, "action", action, action_sz);
    attr(j, "sid", s->sid, sizeof s->sid);
    attr(j, "initiator", s->initiator, sizeof s->initiator);

    const char *jend = strstr(j, "</jingle>"); if (!jend) jend = j + strlen(j);
    const char *cc = j, *ce;
    int content_idx = 0;
    while ((ce = next_elem(&cc, "<content"))) {
        const char *nextc = strstr(cc, "<content");
        const char *span_end = (nextc && nextc < jend) ? nextc : jend;
        char cname[32]; attr(ce, "name", cname, sizeof cname);
        const char *desc = strstr(ce, "<description");
        char media[16] = ""; if (desc && desc < span_end) attr(desc, "media", media, sizeof media);
        int is_video = !strcmp(media, "video");
        if (is_video && content_idx == 0) s->video_first = 1;
        content_idx++;
        jingle_payload *pts = is_video ? s->vpts : s->pts;
        int *pn = is_video ? &s->nvpt : &s->npt;
        if (is_video) { s->has_video = 1; snprintf(s->video_name, sizeof s->video_name, "%s", cname); }
        else if (!s->content_name[0]) snprintf(s->content_name, sizeof s->content_name, "%s", cname);
        const char *pc = ce, *pt;
        while (*pn < JINGLE_MAX_PT && (pt = next_elem(&pc, "<payload-type")) && pt < span_end) {
            jingle_payload *p = &pts[*pn];
            p->id = attr_int(pt, "id");
            attr(pt, "name", p->name, sizeof p->name);
            p->clockrate = attr_int(pt, "clockrate");
            p->channels = attr_int(pt, "channels"); if (p->channels == 0) p->channels = 1;
            (*pn)++;
        }
        const char *src = strstr(ce, "<source ");
        char sb[16];
        if (src && src < span_end && attr(src, "ssrc", sb, sizeof sb)) {
            unsigned v = (unsigned)strtoul(sb, NULL, 10);
            if (is_video) s->vssrc = v; else s->ssrc = v;
        }
    }

    const char *tr = strstr(j, "<transport");
    if (tr) {
        attr(tr, "ufrag", s->ufrag, sizeof s->ufrag);
        attr(tr, "pwd", s->pwd, sizeof s->pwd);
    }

    const char *fpe = strstr(j, "<fingerprint");
    if (fpe) {
        attr(fpe, "setup", s->setup, sizeof s->setup);
        attr(fpe, "hash", s->fp_hash, sizeof s->fp_hash);
        const char *gt = strchr(fpe, '>'), *end = gt ? strstr(gt, "</fingerprint>") : NULL;
        if (gt && end) {
            const char *b = gt + 1;
            while (b < end && (*b == ' ' || *b == '\t' || *b == '\n' || *b == '\r')) b++;
            const char *e = end;
            while (e > b && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r')) e--;
            size_t L = (size_t)(e - b); if (L >= sizeof s->fingerprint) L = sizeof s->fingerprint - 1;
            memcpy(s->fingerprint, b, L); s->fingerprint[L] = '\0';
        }
    }
    const char *cur = j;
    const char *cn;
    while (s->ncand < JINGLE_MAX_CAND && (cn = next_elem(&cur, "<candidate"))) {
        jingle_candidate *c = &s->cand[s->ncand];
        attr(cn, "foundation", c->foundation, sizeof c->foundation);
        c->component = attr_int(cn, "component");
        attr(cn, "ip", c->ip, sizeof c->ip);
        c->port = attr_int(cn, "port");
        c->priority = attr_int(cn, "priority");
        attr(cn, "type", c->type, sizeof c->type);
        if (!attr(cn, "protocol", c->protocol, sizeof c->protocol)) snprintf(c->protocol, sizeof c->protocol, "udp");
        s->ncand++;
    }
    return 1;
}

static int build_session(char *out, size_t osz, const char *from, const jingle_session *s,
                         const char *action, const char *iq_id) {
    int n = 0;
    #define APP(...) do { int _w = snprintf(out + n, osz - (size_t)n, __VA_ARGS__); \
                          if (_w < 0 || (size_t)(n + _w) >= osz) return 0; n += _w; } while (0)
    const char *who_attr = !strcmp(action, "session-initiate") ? "initiator" : "responder";
    const char *aname = s->content_name[0] ? s->content_name : "audio";
    const char *vname = s->video_name[0] ? s->video_name : "video";
    const char *FB = "urn:xmpp:jingle:apps:rtp:rtcp-fb:0";

    #define APP_TRANSPORT() do { \
        APP("<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='%s' pwd='%s'>", s->ufrag, s->pwd); \
        if (s->fingerprint[0]) \
            APP("<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' setup='%s' hash='%s'>%s</fingerprint>", \
                s->setup[0] ? s->setup : "actpass", s->fp_hash[0] ? s->fp_hash : "sha-256", s->fingerprint); \
        for (int _i = 0; _i < s->ncand; _i++) { const jingle_candidate *c = &s->cand[_i]; \
            APP("<candidate foundation='%s' component='%d' protocol='%s' ip='%s' port='%d' priority='%d' type='%s'/>", \
                c->foundation, c->component, c->protocol[0] ? c->protocol : "udp", c->ip, c->port, c->priority, \
                c->type[0] ? c->type : "host"); } \
        APP("</transport>"); } while (0)

    #define APP_AUDIO() do { \
        APP("<content creator='initiator' name='%s'>", aname); \
        APP("<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>"); \
        for (int _i = 0; _i < s->npt; _i++) \
            APP("<payload-type id='%d' name='%s' clockrate='%d' channels='%d'/>", \
                s->pts[_i].id, s->pts[_i].name, s->pts[_i].clockrate, s->pts[_i].channels); \
        APP("<rtcp-mux/>"); \
        if (s->ssrc) \
            APP("<source ssrc='%u' xmlns='urn:xmpp:jingle:apps:rtp:ssma:0'><parameter name='cname' value='%s'/></source>", \
                s->ssrc, s->cname[0] ? s->cname : "trichat"); \
        APP("</description>"); APP_TRANSPORT(); APP("</content>"); } while (0)
    #define APP_VIDEO() do { \
        APP("<content creator='initiator' name='%s'>", vname); \
        APP("<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='video'>"); \
        for (int _i = 0; _i < s->nvpt; _i++) { \
            APP("<payload-type id='%d' name='%s' clockrate='%d'>", s->vpts[_i].id, s->vpts[_i].name, \
                s->vpts[_i].clockrate ? s->vpts[_i].clockrate : 90000); \
            APP("<rtcp-fb xmlns='%s' type='nack'/><rtcp-fb xmlns='%s' type='nack' subtype='pli'/>" \
                "<rtcp-fb xmlns='%s' type='ccm' subtype='fir'/>", FB, FB, FB); \
            if (!strcmp(s->vpts[_i].name, "H264"))     \
                APP("<parameter name='level-asymmetry-allowed' value='1'/>" \
                    "<parameter name='packetization-mode' value='1'/>" \
                    "<parameter name='profile-level-id' value='42e01f'/>"); \
            APP("</payload-type>"); } \
        APP("<rtcp-mux/>"); \
        if (s->vssrc) \
            APP("<source ssrc='%u' xmlns='urn:xmpp:jingle:apps:rtp:ssma:0'><parameter name='cname' value='%s'/></source>", \
                s->vssrc, s->cname[0] ? s->cname : "trichat"); \
        APP("</description>"); APP_TRANSPORT(); APP("</content>"); } while (0)

    APP("<iq type='set' id='%s' to='%s'>", iq_id ? iq_id : "jingle", s->peer);
    APP("<jingle xmlns='urn:xmpp:jingle:1' action='%s' %s='%s' sid='%s'>", action, who_attr, from, s->sid);
    if (s->has_video && s->video_first) {
        APP_VIDEO(); APP_AUDIO();
        APP("<group xmlns='urn:xmpp:jingle:apps:grouping:0' semantics='BUNDLE'>"
            "<content name='%s'/><content name='%s'/></group>", vname, aname);
    } else {
        APP_AUDIO();
        if (s->has_video) {
            APP_VIDEO();
            APP("<group xmlns='urn:xmpp:jingle:apps:grouping:0' semantics='BUNDLE'>"
                "<content name='%s'/><content name='%s'/></group>", aname, vname);
        }
    }
    APP("</jingle></iq>");
    #undef APP_VIDEO
    #undef APP_AUDIO
    #undef APP_TRANSPORT
    #undef APP
    return n;
}

int jingle_build_initiate(char *out, size_t osz, const char *from, const jingle_session *s, const char *iq_id) {
    return build_session(out, osz, from, s, "session-initiate", iq_id);
}
int jingle_build_accept(char *out, size_t osz, const char *from, const jingle_session *s, const char *iq_id) {
    return build_session(out, osz, from, s, "session-accept", iq_id);
}
int jingle_build_transport_info(char *out, size_t osz, const char *from, const jingle_session *s, const char *iq_id) {
    int n = 0;
    #define APP(...) do { int _w = snprintf(out + n, osz - (size_t)n, __VA_ARGS__); \
                          if (_w < 0 || (size_t)(n + _w) >= osz) return 0; n += _w; } while (0)
    APP("<iq type='set' id='%s' to='%s'>", iq_id ? iq_id : "jingle", s->peer);
    APP("<jingle xmlns='urn:xmpp:jingle:1' action='transport-info' initiator='%s' sid='%s'>", from, s->sid);
    APP("<content creator='initiator' name='%s'>", s->content_name[0] ? s->content_name : "audio");
    APP("<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='%s' pwd='%s'>", s->ufrag, s->pwd);
    for (int i = 0; i < s->ncand; i++) {
        const jingle_candidate *c = &s->cand[i];
        APP("<candidate foundation='%s' component='%d' protocol='%s' ip='%s' port='%d' priority='%d' type='%s'/>",
            c->foundation, c->component, c->protocol[0] ? c->protocol : "udp", c->ip, c->port, c->priority,
            c->type[0] ? c->type : "host");
    }
    APP("</transport></content></jingle></iq>");
    #undef APP
    return n;
}

int jingle_build_terminate(char *out, size_t osz, const char *from, const jingle_session *s, const char *reason, const char *iq_id) {
    (void)from;
    int n = snprintf(out, osz,
        "<iq type='set' id='%s' to='%s'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='%s'>"
        "<reason><%s/></reason></jingle></iq>",
        iq_id ? iq_id : "jingle", s->peer, s->sid, reason && reason[0] ? reason : "success");
    return (n < 0 || (size_t)n >= osz) ? 0 : n;
}

int jingle_selftest(void) {
    jingle_session out; memset(&out, 0, sizeof out);
    snprintf(out.sid, sizeof out.sid, "a73sjjvkla37jfea");
    snprintf(out.peer, sizeof out.peer, "romeo@montague.example/orchard");
    snprintf(out.content_name, sizeof out.content_name, "audio");
    out.pts[0] = (jingle_payload){ 111, "opus", 48000, 2 };
    out.pts[1] = (jingle_payload){ 0, "PCMU", 8000, 1 };
    out.npt = 2;
    snprintf(out.ufrag, sizeof out.ufrag, "8hhy");
    snprintf(out.pwd, sizeof out.pwd, "asd88fgpdd777uzjYhagZg");
    snprintf(out.setup, sizeof out.setup, "actpass");
    snprintf(out.fp_hash, sizeof out.fp_hash, "sha-256");
    snprintf(out.fingerprint, sizeof out.fingerprint, "AB:CD:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC");
    out.cand[0] = (jingle_candidate){ "1", 1, "10.0.1.1", 8998, 2130706431, "host", "udp" };
    out.cand[1] = (jingle_candidate){ "2", 1, "192.0.2.3", 45664, 1694498815, "srflx", "udp" };
    out.ncand = 2;

    char buf[2048];
    int w = jingle_build_initiate(buf, sizeof buf, "juliet@capulet.example/balcony", &out, "call1");
    if (w <= 0) { fprintf(stderr, "jingle: build_initiate overflow/err\n"); return -1; }

    jingle_session in; char action[32];
    if (!jingle_parse(buf, &in, action, sizeof action)) { fprintf(stderr, "jingle: parse rejected our own stanza\n"); return -1; }
    if (strcmp(action, "session-initiate")) { fprintf(stderr, "jingle: action '%s' != session-initiate\n", action); return -1; }
    if (strcmp(in.sid, out.sid)) { fprintf(stderr, "jingle: sid lost\n"); return -1; }
    if (strcmp(in.initiator, "juliet@capulet.example/balcony")) { fprintf(stderr, "jingle: initiator lost\n"); return -1; }
    if (strcmp(in.content_name, "audio")) { fprintf(stderr, "jingle: content name lost\n"); return -1; }
    if (in.npt != 2 || in.pts[0].id != 111 || strcmp(in.pts[0].name, "opus") || in.pts[0].clockrate != 48000 || in.pts[0].channels != 2)
        { fprintf(stderr, "jingle: opus payload-type not round-tripped\n"); return -1; }
    if (in.pts[1].id != 0 || strcmp(in.pts[1].name, "PCMU") || in.pts[1].channels != 1)
        { fprintf(stderr, "jingle: second payload-type not round-tripped\n"); return -1; }
    if (strcmp(in.ufrag, "8hhy") || strcmp(in.pwd, "asd88fgpdd777uzjYhagZg"))
        { fprintf(stderr, "jingle: ICE creds lost\n"); return -1; }
    if (strcmp(in.setup, "actpass") || strcmp(in.fp_hash, "sha-256") ||
        strcmp(in.fingerprint, "AB:CD:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC"))
        { fprintf(stderr, "jingle: DTLS fingerprint not round-tripped\n"); return -1; }
    if (in.ncand != 2 || strcmp(in.cand[0].ip, "10.0.1.1") || in.cand[0].port != 8998 ||
        strcmp(in.cand[0].type, "host") || in.cand[0].priority != 2130706431)
        { fprintf(stderr, "jingle: host candidate not round-tripped\n"); return -1; }
    if (strcmp(in.cand[1].type, "srflx") || in.cand[1].port != 45664 || strcmp(in.cand[1].ip, "192.0.2.3"))
        { fprintf(stderr, "jingle: srflx candidate not round-tripped\n"); return -1; }

    char tb[512];
    if (jingle_build_terminate(tb, sizeof tb, NULL, &out, "decline", "call1") <= 0 ||
        !strstr(tb, "session-terminate") || !strstr(tb, "<decline/>") || !strstr(tb, out.sid))
        { fprintf(stderr, "jingle: terminate stanza malformed\n"); return -1; }

    char xb[1024];
    if (jingle_build_transport_info(xb, sizeof xb, "juliet@capulet.example/balcony", &out, "ti1") <= 0)
        { fprintf(stderr, "jingle: transport-info build failed\n"); return -1; }
    jingle_session ti; char tact[32];
    if (!jingle_parse(xb, &ti, tact, sizeof tact) || strcmp(tact, "transport-info"))
        { fprintf(stderr, "jingle: transport-info action lost\n"); return -1; }
    if (strcmp(ti.sid, out.sid) || ti.ncand != 2 || strcmp(ti.cand[0].ip, "10.0.1.1") || ti.cand[1].port != 45664)
        { fprintf(stderr, "jingle: transport-info candidates not round-tripped\n"); return -1; }
    if (strstr(xb, "<description"))
        { fprintf(stderr, "jingle: transport-info leaked a description\n"); return -1; }

    jingle_session v = out;
    v.has_video = 1; snprintf(v.video_name, sizeof v.video_name, "1");
    v.vpts[0] = (jingle_payload){ 96, "VP8", 90000, 1 }; v.nvpt = 1; v.vssrc = 0xC0FFEE;
    char vb[3072];
    if (jingle_build_initiate(vb, sizeof vb, "juliet@capulet.example/balcony", &v, "vcall") <= 0)
        { fprintf(stderr, "jingle: video initiate overflow\n"); return -1; }
    if (!strstr(vb, "media='video'") || !strstr(vb, "name='VP8'") || !strstr(vb, "semantics='BUNDLE'"))
        { fprintf(stderr, "jingle: video content/group not built\n"); return -1; }
    jingle_session vi; char vact[32];
    if (!jingle_parse(vb, &vi, vact, sizeof vact)) { fprintf(stderr, "jingle: video parse failed\n"); return -1; }
    if (!vi.has_video || strcmp(vi.video_name, "1")) { fprintf(stderr, "jingle: video content not detected\n"); return -1; }
    if (vi.nvpt != 1 || vi.vpts[0].id != 96 || strcmp(vi.vpts[0].name, "VP8") || vi.vssrc != 0xC0FFEE)
        { fprintf(stderr, "jingle: video payload/ssrc not round-tripped\n"); return -1; }
    if (vi.npt != 2 || vi.pts[0].id != 111 || strcmp(vi.pts[0].name, "opus"))
        { fprintf(stderr, "jingle: audio payloads corrupted by the video content\n"); return -1; }

    jingle_session vf = v; vf.video_first = 1;
    char fb[3072];
    if (jingle_build_initiate(fb, sizeof fb, "juliet@capulet.example/balcony", &vf, "vf") <= 0)
        { fprintf(stderr, "jingle: video-first build overflow\n"); return -1; }
    const char *mv = strstr(fb, "media='video'"), *ma = strstr(fb, "media='audio'");
    if (!mv || !ma || mv > ma) { fprintf(stderr, "jingle: video-first order not honored\n"); return -1; }
    jingle_session vfi; char vfa[32];
    if (!jingle_parse(fb, &vfi, vfa, sizeof vfa) || !vfi.video_first)
        { fprintf(stderr, "jingle: video_first not detected on parse\n"); return -1; }
    return 0;
}
