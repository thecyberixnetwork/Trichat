#include "trichat.h"
#include "util.h"
#include "resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/socket.h>

#ifdef TRI_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif

enum { ST_RESOLVING, ST_CONNECTING, ST_TLS_HS, ST_ONLINE };

typedef struct {
    char host[256], port[8], nick[64], user[64], realname[128], pass[160];
    tri_resolve *resolve;
    char autojoin[256];
    int  tls;
    int  state;
    int  registered;
    int  sasl_done;
    int  cap_want_sasl;
    char rbuf[8192];
    size_t rlen;
#ifdef TRI_TLS
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
#endif
} irc_priv;

static ssize_t io_write(irc_priv *p, int fd, const char *b, size_t n) {
#ifdef TRI_TLS
    if (p->tls) return wolfSSL_write(p->ssl, b, n);
#endif
    (void)p; return write(fd, b, n);
}
static ssize_t io_read(irc_priv *p, int fd, char *b, size_t n) {
#ifdef TRI_TLS
    if (p->tls) return wolfSSL_read(p->ssl, b, n);
#endif
    (void)p; return read(fd, b, n);
}

static void emit(account_t *a, tri_event_kind k, const char *target, const char *text) {
    tri_event_t ev = { k, tri_account_key(a), target, text, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static int sendf(account_t *a, const char *fmt, ...) {
    irc_priv *p = tri_account_priv(a);
    char line[1024];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof line) return tri_set_error("irc: outgoing line too long");
    if (io_write(p, tri_account_fd(a), line, n) != n)
        return tri_set_error("irc: write failed on '%s': %s", tri_account_name(a), strerror(errno));
    return 0;
}

static int parse_url(irc_priv *p, const char *url) {
    char buf[600];
    snprintf(buf, sizeof buf, "%s", url ? url : "");
    char *s = buf;

    if (!strncmp(s, "ircs://", 7))      { p->tls = 1; s += 7; }
    else if (!strncmp(s, "irc://", 6))  { p->tls = 0; s += 6; }
    else return tri_set_error("irc: config must start with irc:// or ircs:// (got '%s')", url);

    char *chans = strchr(s, '/');
    if (chans) { *chans++ = '\0'; snprintf(p->autojoin, sizeof p->autojoin, "%s", chans); }

    char *at = strrchr(s, '@');
    if (at) {
        *at = '\0';
        char *colon = strchr(s, ':');
        if (colon) { *colon = '\0'; snprintf(p->pass, sizeof p->pass, "%s", colon + 1); }
        snprintf(p->nick, sizeof p->nick, "%s", s);
        s = at + 1;
    }
    if (!*s) return tri_set_error("irc: no host in config '%s'", url);

    char *pcolon = strchr(s, ':');
    if (pcolon) { *pcolon = '\0'; snprintf(p->port, sizeof p->port, "%s", pcolon + 1); }
    else snprintf(p->port, sizeof p->port, "%s", p->tls ? "6697" : "6667");
    snprintf(p->host, sizeof p->host, "%s", s);

    if (!p->nick[0]) return tri_set_error("irc: no nick in config (use irc://nick@host)");
    snprintf(p->user, sizeof p->user, "%s", p->nick);
    snprintf(p->realname, sizeof p->realname, "Trichat %s", p->nick);
    return 0;
}

static void send_registration(account_t *a) {
    irc_priv *p = tri_account_priv(a);
    emit(a, TRI_EV_STATUS, NULL, p->tls ? "TLS up, registering" : "TCP up, registering");

    sendf(a, "CAP LS 302\r\n");
    sendf(a, "NICK %s\r\n", p->nick);
    sendf(a, "USER %s 0 * :%s\r\n", p->user, p->realname);
}

static void irc_teardown(account_t *a, const char *why);

#ifdef TRI_TLS

static void tls_pump(account_t *a) {
    irc_priv *p = tri_account_priv(a);
    if (wolfSSL_connect(p->ssl) == WOLFSSL_SUCCESS) {
        tri_account_set_write_interest(a, 0);
        p->state = ST_ONLINE;
        send_registration(a);
        return;
    }
    int err = wolfSSL_get_error(p->ssl, 0);
    if (err == WOLFSSL_ERROR_WANT_WRITE) { tri_account_set_write_interest(a, 1); return; }
    if (err == WOLFSSL_ERROR_WANT_READ)  { tri_account_set_write_interest(a, 0); return; }
    char e[80]; wolfSSL_ERR_error_string(err, e);
    tri_set_error("irc: TLS handshake with %s failed: %s", p->host, e);
    char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
    irc_teardown(a, NULL);
    tri_account_notify_down(a, m);
}
#endif

static void irc_resolved(void *ud, int ok, const struct sockaddr *sa, socklen_t salen,
                         int socktype, int proto, const char *err) {
    account_t *a = ud;
    irc_priv *p = tri_account_priv(a);
    if (!p) return;
    p->resolve = NULL;
    if (!ok) {
        tri_set_error("irc: cannot resolve %s:%s: %s", p->host, p->port, err);
        char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
        irc_teardown(a, NULL); tri_account_notify_down(a, m); return;
    }
    int fd = socket(sa->sa_family, socktype, proto);
    if (fd < 0) { tri_set_error("irc: socket() failed: %s", strerror(errno));
                  char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                  irc_teardown(a, NULL); tri_account_notify_down(a, m); return; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int rc = connect(fd, sa, salen);
    if (rc != 0 && errno != EINPROGRESS) {
        tri_set_error("irc: connect to %s:%s failed: %s", p->host, p->port, strerror(errno));
        char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
        close(fd); irc_teardown(a, NULL); tri_account_notify_down(a, m); return;
    }
    tri_account_set_fd(a, fd);
    p->state = ST_CONNECTING;
    tri_account_set_write_interest(a, 1);

#ifdef TRI_TLS
    if (p->tls) {
        static int inited = 0;
        if (!inited) { wolfSSL_Init(); inited = 1; }
        p->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        if (!p->ctx) { tri_set_error("irc: wolfSSL_CTX_new failed");
                       char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                       irc_teardown(a, NULL); tri_account_notify_down(a, m); return; }
        wolfSSL_CTX_load_system_CA_certs(p->ctx);
        wolfSSL_CTX_set_verify(p->ctx, WOLFSSL_VERIFY_PEER, NULL);
        p->ssl = wolfSSL_new(p->ctx);
        wolfSSL_set_fd(p->ssl, fd);
        wolfSSL_check_domain_name(p->ssl, p->host);
    }
#endif
    emit(a, TRI_EV_STATUS, NULL, "connecting...");
}

static int irc_connect(account_t *a) {
    irc_priv *p = calloc(1, sizeof *p);
    if (!p) return tri_set_error("irc: out of memory");
    if (parse_url(p, tri_account_config(a)) != 0) { free(p); return -1; }
#ifndef TRI_TLS
    if (p->tls) { free(p); return tri_set_error("irc: ircs:// needs a TLS build (rebuild with wolfSSL); use irc:// for plaintext"); }
#endif
    tri_account_set_priv(a, p);
    p->state = ST_RESOLVING;
    p->resolve = tri_resolve_start(tri_account_core(a), p->host, p->port, SOCK_STREAM, irc_resolved, a);
    if (!p->resolve) { free(p); tri_account_set_priv(a, NULL); return -1; }
    emit(a, TRI_EV_STATUS, NULL, "resolving...");
    return 0;
}

static void irc_teardown(account_t *a, const char *why) {
    irc_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->resolve) { tri_resolve_cancel(p->resolve); p->resolve = NULL; }
    int fd = tri_account_fd(a);
    if (fd >= 0) {
#ifdef TRI_TLS
        if (p->ssl) { if (p->state == ST_ONLINE) wolfSSL_shutdown(p->ssl); wolfSSL_free(p->ssl); }
        if (p->ctx) wolfSSL_CTX_free(p->ctx);
#endif
        close(fd);
    }
    tri_account_set_write_interest(a, 0);
    tri_roster_clear_account(a);
    if (why) emit(a, TRI_EV_STATUS, NULL, why);
    free(p);
    tri_account_set_priv(a, NULL);
    tri_account_set_fd(a, -1);
}

static void irc_disconnect(account_t *a) {
    irc_priv *p = tri_account_priv(a);
    if (p && p->state == ST_ONLINE && tri_account_fd(a) >= 0)
        io_write(p, tri_account_fd(a), "QUIT :Trichat\r\n", 15);
    irc_teardown(a, p ? "disconnected" : NULL);
}

static void irc_on_writable(account_t *a, int fd) {
    irc_priv *p = tri_account_priv(a);
    if (!p) return;
    if (p->state == ST_CONNECTING) {
        int err = 0; socklen_t len = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err) { char host[128], port[16]; snprintf(host, sizeof host, "%s", p->host); snprintf(port, sizeof port, "%s", p->port);
                   tri_set_error("irc: connect to %s:%s failed: %s", host, port, strerror(err));
                   char m[256]; snprintf(m, sizeof m, "%s", tri_last_error());
                   irc_teardown(a, NULL); tri_account_notify_down(a, m); return; }
#ifdef TRI_TLS
        if (p->tls) { p->state = ST_TLS_HS; tls_pump(a); return; }
#endif
        tri_account_set_write_interest(a, 0);
        p->state = ST_ONLINE;
        send_registration(a);
        return;
    }
#ifdef TRI_TLS
    if (p->state == ST_TLS_HS) tls_pump(a);
#endif
}

static int irc_send(account_t *a, const char *target, const char *body) {
    irc_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE)
        return tri_set_error("irc: not connected yet - can't send to %s", target);
    return sendf(a, "PRIVMSG %s :%s\r\n", target, body);
}

static int irc_raw(account_t *a, const char *line) {
    irc_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("irc: not connected yet - can't run that command");
    return sendf(a, "%s\r\n", line);
}

static int irc_action(account_t *a, const char *target, const char *body) {
    irc_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("irc: not connected yet - can't send to %s", target);
    return sendf(a, "PRIVMSG %s :\x01" "ACTION %s\x01\r\n", target, body);
}

static int irc_moderate(account_t *a, const char *channel, const char *user, const char *action, const char *arg) {
    irc_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("irc: not connected yet");
    if (!channel || !channel[0]) return tri_set_error("irc: moderation needs a channel");
    if (!strcmp(action, "kick"))        return sendf(a, "KICK %s %s :%s\r\n", channel, user, (arg && arg[0]) ? arg : "kicked");
    if (!strcmp(action, "ban"))         return sendf(a, "MODE %s +b %s!*@*\r\n", channel, user);
    if (!strcmp(action, "unban"))       return sendf(a, "MODE %s -b %s!*@*\r\n", channel, user);
    if (!strcmp(action, "op"))          return sendf(a, "MODE %s +o %s\r\n", channel, user);
    if (!strcmp(action, "deop"))        return sendf(a, "MODE %s -o %s\r\n", channel, user);
    if (!strcmp(action, "voice"))       return sendf(a, "MODE %s +v %s\r\n", channel, user);
    if (!strcmp(action, "devoice"))     return sendf(a, "MODE %s -v %s\r\n", channel, user);
    if (!strcmp(action, "mute"))        return sendf(a, "MODE %s +q %s!*@*\r\n", channel, user);
    if (!strcmp(action, "unmute"))      return sendf(a, "MODE %s -q %s!*@*\r\n", channel, user);
    return tri_set_error("irc: unsupported moderation action '%s'", action);
}

static int irc_user_info(account_t *a, const char *channel, const char *user) {
    (void)channel;
    irc_priv *p = tri_account_priv(a);
    if (!p || p->state != ST_ONLINE) return tri_set_error("irc: not connected yet");
    return sendf(a, "WHOIS %s\r\n", user);
}

static void do_join(account_t *a, const char *target) { sendf(a, "JOIN %s\r\n", target); }

static void irc_join(account_t *a, const char *target) {
    irc_priv *p = tri_account_priv(a);
    if (p->registered) do_join(a, target);
    else {
        size_t len = strlen(p->autojoin);
        snprintf(p->autojoin + len, sizeof p->autojoin - len, "%s%s", len ? "," : "", target);
    }
}

static void irc_leave(account_t *a, const char *target) {
    irc_priv *p = tri_account_priv(a);
    if (p && p->registered) sendf(a, "PART %s\r\n", target);
}

static const char *nick_of(char *prefix) {
    char *bang = strchr(prefix, '!');
    if (bang) *bang = '\0';
    return prefix;
}

static long long days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    long long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long long)doe - 719468;
}

static long long parse_server_time(const char *v) {
    int Y, M, D, h, mi, s;
    if (sscanf(v, "%d-%d-%dT%d:%d:%d", &Y, &M, &D, &h, &mi, &s) != 6) return 0;
    return days_from_civil(Y, M, D) * 86400LL + h * 3600LL + mi * 60LL + s;
}

static void tag_value(const char *tags, const char *key, char *out, size_t osz) {
    out[0] = '\0'; if (!tags) return;
    size_t kl = strlen(key);
    for (const char *p = tags; *p; ) {
        const char *semi = strchr(p, ';'); const char *endt = semi ? semi : p + strlen(p);
        if ((size_t)(endt - p) > kl && p[kl] == '=' && !strncmp(p, key, kl)) {
            const char *val = p + kl + 1; size_t vl = (size_t)(endt - val);
            if (vl >= osz) vl = osz - 1;
            memcpy(out, val, vl); out[vl] = '\0'; return;
        }
        if (!semi) break;
        p = semi + 1;
    }
}

static void handle_line(account_t *a, char *line) {
    irc_priv *p = tri_account_priv(a);

    char *tags = NULL;
    if (line[0] == '@') {
        tags = line + 1;
        char *sp = strchr(line, ' '); if (!sp) return;
        *sp = '\0'; line = sp + 1;
        while (*line == ' ') line++;
    }
    char timetag[40]; tag_value(tags, "time", timetag, sizeof timetag);
    long long ts = timetag[0] ? parse_server_time(timetag) : 0;

    char *prefix = NULL;
    if (line[0] == ':') { prefix = line + 1; char *sp = strchr(line, ' '); if (!sp) return; *sp = '\0'; line = sp + 1; }
    char *cmd = line;
    char *args = strchr(line, ' ');
    if (args) *args++ = '\0';
    char *trailing = args ? strstr(args, " :") : NULL;
    if (trailing) { *trailing = '\0'; trailing += 2; }
    else if (args && args[0] == ':') trailing = args + 1;

    if (!strcmp(cmd, "PING")) {
        sendf(a, "PONG :%s\r\n", trailing ? trailing : (args ? args : ""));
        return;
    }
    if (!strcmp(cmd, "PRIVMSG") || !strcmp(cmd, "NOTICE")) {
        char *target = args ? strtok(args, " ") : NULL;
        const char *who = prefix ? nick_of(prefix) : "?";
        const char *body = trailing ? trailing : "";
        int is_notice = cmd[0] == 'N';

        int to_channel = target && strchr("#&!+", target[0]);
        int server_src = !prefix || strchr(who, '.');
        const char *convo = to_channel ? target
                          : (is_notice && server_src) ? NULL
                          : who;

        char act[1100];
        if (body[0] == '\x01' && !strncmp(body + 1, "ACTION ", 7)) {
            snprintf(act, sizeof act, "%s", body + 8);
            char *z = strrchr(act, '\x01'); if (z) *z = '\0';
            char line[1160]; snprintf(line, sizeof line, "* %s %s", who, act);
            tri_event_t aev = { TRI_EV_STATUS, tri_account_key(a), convo, line, NULL, ts, 0, 0, NULL };
            tri_emit(tri_account_core(a), &aev);
            return;
        }
        tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), convo, body, who, ts, 0, 0, NULL };
        tri_emit(tri_account_core(a), &ev);
        return;
    }
    if (!strcmp(cmd, "JOIN") || !strcmp(cmd, "PART")) {
        const char *who = prefix ? nick_of(prefix) : "?";
        int joined = cmd[0] == 'J';

        char chan[128] = "";
        const char *src = (args && *args) ? args : trailing;
        if (src) { while (*src == ' ' || *src == ':') src++; snprintf(chan, sizeof chan, "%s", src); char *sp = strchr(chan, ' '); if (sp) *sp = '\0'; }
        int self = who && p->nick[0] && !strcasecmp(who, p->nick);
        if (chan[0]) {
            if (joined) { tri_roster_upsert(a, chan, who, 0);   if (self) tri_channel_set_member(a, chan, 1); }
            else        { tri_roster_remove_from(a, chan, who); if (self) tri_channel_set_member(a, chan, 0); }
        }
        char msg[256]; snprintf(msg, sizeof msg, "%s %s %s", who, joined ? "joined" : "left", chan);
        emit(a, TRI_EV_STATUS, chan[0] ? chan : NULL, msg);
        return;
    }
    if (!strcmp(cmd, "QUIT")) {
        const char *who = prefix ? nick_of(prefix) : "?";
        tri_roster_remove(a, who);
        char msg[300]; snprintf(msg, sizeof msg, "%s quit%s%s%s", who, trailing ? " (" : "", trailing ? trailing : "", trailing ? ")" : "");
        emit(a, TRI_EV_STATUS, NULL, msg);
        return;
    }
    if (!strcmp(cmd, "KICK")) {
        char *chan = args ? strtok(args, " ") : NULL;
        char *target = chan ? strtok(NULL, " ") : NULL;
        if (chan && target) tri_roster_remove_from(a, chan, target);
        if (chan && target && p->nick[0] && !strcasecmp(target, p->nick)) tri_channel_set_member(a, chan, 0);
        char msg[300]; snprintf(msg, sizeof msg, "%s was kicked from %s%s%s", target ? target : "?", chan ? chan : "?", trailing ? " : " : "", trailing ? trailing : "");
        emit(a, TRI_EV_STATUS, chan, msg);
        return;
    }
    if (!strcmp(cmd, "NICK")) {
        const char *oldn = prefix ? nick_of(prefix) : NULL;
        const char *newn = trailing ? trailing : args;
        if (newn && *newn == ':') newn++;
        if (oldn && newn && *newn) {
            tri_core *co = tri_account_core(a); const char *mykey = tri_account_key(a);
            char chans[64][128]; int nc = 0;
            for (int i = 0; i < tri_roster_count(co) && nc < 64; i++) {
                const char *ak = NULL, *ch = NULL, *us = NULL; int tk = 0; tri_roster_get(co, i, &ak, &ch, &us, &tk);
                if (!strcmp(ak, mykey) && !strcmp(us, oldn)) snprintf(chans[nc++], 128, "%s", ch);
            }
            for (int i = 0; i < nc; i++) { tri_roster_remove_from(a, chans[i], oldn); tri_roster_upsert(a, chans[i], newn, 0); }
            if (p->nick[0] && !strcasecmp(oldn, p->nick)) snprintf(p->nick, sizeof p->nick, "%s", newn);
        }
        char msg[200]; snprintf(msg, sizeof msg, "%s is now known as %s", oldn ? oldn : "?", newn ? newn : "?");
        emit(a, TRI_EV_STATUS, NULL, msg);
        return;
    }
    if (!strcmp(cmd, "353")) {
        char *chan = NULL;
        if (args) for (char *t = strtok(args, " "); t; t = strtok(NULL, " ")) chan = t;
        if (chan && trailing)
            for (char *n = strtok(trailing, " "); n; n = strtok(NULL, " ")) {
                while (*n == '@' || *n == '+' || *n == '%' || *n == '~' || *n == '&') n++;
                if (*n) tri_roster_upsert(a, chan, n, 0);
            }
        return;
    }
    if (!strcmp(cmd, "TOPIC") || !strcmp(cmd, "332")) {
        emit(a, TRI_EV_STATUS, NULL, trailing ? trailing : "topic");
        return;
    }
    if (!strcmp(cmd, "CAP")) {
        char *sub = args ? strtok(args, " ") : NULL;
        char *verb = sub ? strtok(NULL, " ") : NULL;
        if (verb && (!strcmp(verb, "LS") || !strcmp(verb, "NEW")) && trailing) {
            static const char *want[] = {
                "multi-prefix", "server-time", "message-tags", "account-notify",
                "away-notify", "extended-join", "chghost", "account-tag",
                "invite-notify", "setname", "sasl" };
            char have[600]; snprintf(have, sizeof have, " %s ", trailing);
            char req[400]; size_t rl = 0;
            for (size_t i = 0; i < sizeof want / sizeof *want; i++) {
                char tok[40]; int tl = snprintf(tok, sizeof tok, " %s", want[i]);
                char *h = strstr(have, tok);
                if (!h || (h[tl] != ' ' && h[tl] != '=')) continue;
                if (!strcmp(want[i], "sasl")) { if (!p->pass[0]) continue; p->cap_want_sasl = 1; }
                rl += snprintf(req + rl, sizeof req - rl, "%s%s", rl ? " " : "", want[i]);
            }
            if (rl) sendf(a, "CAP REQ :%s\r\n", req);
            else    sendf(a, "CAP END\r\n");
        } else if (verb && !strcmp(verb, "ACK")) {
            if (p->cap_want_sasl && trailing && strstr(trailing, "sasl")) sendf(a, "AUTHENTICATE PLAIN\r\n");
            else sendf(a, "CAP END\r\n");
        } else if (verb && !strcmp(verb, "NAK")) {
            sendf(a, "CAP END\r\n");
        }
        return;
    }
    if (!strcmp(cmd, "AUTHENTICATE") && args && args[0] == '+') {
        unsigned char raw[400]; int n = 0;
        raw[n++] = 0;
        n += snprintf((char *)raw + n, sizeof raw - n, "%s", p->nick) + 1;
        n += snprintf((char *)raw + n, sizeof raw - n, "%s", p->pass);
        char enc[600]; tri_b64enc(raw, n, enc);
        sendf(a, "AUTHENTICATE %s\r\n", enc);
        return;
    }
    if (!strcmp(cmd, "001")) {
        p->registered = 1;
        tri_account_set_state(a, TRI_CS_ONLINE);
        emit(a, TRI_EV_STATUS, NULL, "registered");
        if (p->pass[0] && !p->sasl_done) sendf(a, "PRIVMSG NickServ :IDENTIFY %s\r\n", p->pass);

        char persisted[512]; tri_channel_member_list(a, persisted, sizeof persisted);
        char autoj[256]; snprintf(autoj, sizeof autoj, "%s", p->autojoin);
        char seen[64][128]; int nseen = 0;
        for (int pass = 0; pass < 2; pass++) {
            char *list = pass ? persisted : autoj;
            for (char *t = strtok(list, ","); t; t = strtok(NULL, ",")) {
                while (*t == ' ') t++;
                char *end = t + strlen(t); while (end > t && end[-1] == ' ') *--end = '\0';
                if (!*t || nseen >= 64) continue;
                int dup = 0; for (int k = 0; k < nseen; k++) if (!strcasecmp(seen[k], t)) { dup = 1; break; }
                if (dup) continue;
                snprintf(seen[nseen++], sizeof seen[0], "%s", t);
                do_join(a, t);
            }
        }
        return;
    }
    if (!strcmp(cmd, "903")) { p->sasl_done = 1; sendf(a, "CAP END\r\n"); emit(a, TRI_EV_STATUS, NULL, "SASL authenticated"); return; }
    if (!strcmp(cmd, "904") || !strcmp(cmd, "905") || !strcmp(cmd, "906")) {
        sendf(a, "CAP END\r\n");
        emit(a, TRI_EV_ERROR, NULL, trailing ? trailing : "SASL failed");
        return;
    }

    if (cmd[0] >= '0' && cmd[0] <= '9' && trailing) {
        int num = atoi(cmd);
        emit(a, num >= 400 ? TRI_EV_ERROR : TRI_EV_STATUS, NULL, trailing);
    }
}

static void irc_on_readable(account_t *a, int fd) {
    irc_priv *p = tri_account_priv(a);
    if (!p) return;
#ifdef TRI_TLS
    if (p->state == ST_TLS_HS) { tls_pump(a); return; }
#endif
    if (p->state != ST_ONLINE) return;

    for (;;) {
        ssize_t r = io_read(p, fd, p->rbuf + p->rlen, sizeof p->rbuf - p->rlen - 1);
        if (r <= 0) {
            int wouldblock;
#ifdef TRI_TLS
            if (p->tls) { int e = wolfSSL_get_error(p->ssl, r);
                          wouldblock = (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE); }
            else
#endif
                wouldblock = (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
            if (wouldblock) return;
            irc_teardown(a, NULL);
            tri_account_notify_down(a, r == 0 ? "connection closed by server" : "connection error");
            return;
        }
        p->rlen += r;
        p->rbuf[p->rlen] = '\0';

        char *start = p->rbuf, *nl;
        while ((nl = strpbrk(start, "\r\n"))) {
            *nl = '\0';
            if (*start) handle_line(a, start);
            if (tri_account_priv(a) == NULL) return;
            start = nl + 1;
            while (*start == '\r' || *start == '\n') start++;
        }
        p->rlen = strlen(start);
        memmove(p->rbuf, start, p->rlen + 1);
        if (p->rlen >= sizeof p->rbuf - 1) {
            irc_teardown(a, NULL);
            tri_account_notify_down(a, "irc: oversized line from server");
            return;
        }
    }
}

const protocol_backend_t backend_irc = {
    .name = "irc",
    .connect = irc_connect,
    .disconnect = irc_disconnect,
    .send_message = irc_send,
    .join = irc_join,
    .leave = irc_leave,
    .on_socket_readable = irc_on_readable,
    .on_socket_writable = irc_on_writable,
    .tick = NULL,
    .raw = irc_raw,
    .send_action = irc_action,
    .moderate = irc_moderate,
    .user_info = irc_user_info,
};
