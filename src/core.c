#include "trichat.h"
#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <strings.h>
#include <math.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

static void mkdir_p(const char *path) {
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    mkdir(tmp, 0700);
}

extern const protocol_backend_t backend_echo;
extern const protocol_backend_t backend_irc;
extern const protocol_backend_t backend_mumble;
extern const protocol_backend_t backend_xmpp;
static const protocol_backend_t *const REGISTRY[] = { &backend_echo, &backend_irc, &backend_mumble, &backend_xmpp };

struct account {
    char name[64];
    char key[96];
    char config[512];
    const protocol_backend_t *backend;
    int fd;
    int want_write;
    void *priv;
    tri_core *core;
    tri_folder_t *folder;
    int order;

    int conn_state;
    int want_connected;
    int autoconnect;
    int insecure;
    int retry_n;
    double next_retry_at;
    char faketyping[128];
    account_t *next;
};

struct tri_folder {
    int id;
    char name[64];
    tri_folder_t *parent;
    int order;
    tri_core *core;
    tri_folder_t *next;
};

#define TRI_MAX_FDS 64
typedef struct { int fd; void (*cb)(void *, int); void *ud; } fd_reg_t;

#define MAX_FOLDER_REFS 1024
typedef struct { int folder_id; char acctkey[96], target[128]; int order; } chanref_t;

#define MAX_ROSTER 2048
typedef struct { char acctkey[96], channel[128], user[128]; int talking; } rentry_t;

#define MAX_CHANTREE 1024
typedef struct { char acctkey[96], name[128]; unsigned id, parent; } cnode_t;

struct tri_core {
    account_t *accounts;
    fd_reg_t fds[TRI_MAX_FDS];
    int nfds;
    void (*on_event)(void *, const tri_event_t *);
    void *ev_ud;
    int running;
    char store[512];
    char fstore[512];
    int  save_warned;
    tri_folder_t *folders;
    int next_folder_id;
    int order_seq;
    chanref_t refs[MAX_FOLDER_REFS];
    int nrefs;
    rentry_t roster[MAX_ROSTER];
    int nroster;
    cnode_t chantree[MAX_CHANTREE];
    int nchantree;
    struct { char acctkey[96], user[128]; } ignores[256];
    int nignores;
    char audio_method[24];
    char audio_device[128];
    char astore[512];

    struct { char acctkey[96], target[128], nick[64]; signed char logmode; signed char encrypt; signed char notify; signed char member; } chans[512];
    int  nchans;
    int  log_global;
    char cstore[512];

    struct { char pattern[128], acctkey[96], target[128]; } rules[128];
    int  nrules;
    char rstore[512];
    struct { char acctkey[96], target[128], nick[64], text[400]; long long ts; } inbox[512];
    int  ninbox;

    struct { char acctkey[96], target[128], nick[64], text[400]; long long ts; } saved[256];
    int  nsaved;
    char sstore[512];

    struct { char acctkey[96]; int which, w, h; unsigned gen; uint8_t *buf; size_t cap; } vframes[8];
    int  nvframes;
};

static tri_core *g_core;

static void save_accounts(tri_core *c);
static void save_folders(tri_core *c);
static void save_channels(tri_core *c);
static void save_rules(tri_core *c);
static void save_failed(tri_core *c, const char *path);

static char g_err[256] = "no error";
const char *tri_last_error(void) { return g_err; }
int tri_set_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap);
    va_end(ap);
    return -1;
}

static double now_s(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) return ts.tv_sec + ts.tv_nsec / 1e9;
    return (double)time(NULL);
}

void tri_log(tri_core *c, const char *fmt, ...) {
    if (!c || !c->on_event) return;
    char msg[512]; va_list ap; va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    tri_event_t ev = { TRI_EV_STATUS, "*:debug", "", msg, NULL, 0 };
    c->on_event(c->ev_ud, &ev);
}

tri_core *tri_core_new(void (*on_event)(void *, const tri_event_t *), void *ud) {
    tri_core *c = calloc(1, sizeof *c);
    if (!c) { tri_set_error("out of memory allocating core"); return NULL; }
    c->on_event = on_event;
    c->ev_ud = ud;
    c->next_folder_id = 1;
    g_core = c;
    return c;
}

void tri_core_free(tri_core *c) {
    if (!c) return;
    tri_http_shutdown(c);

    while (c->accounts) {
        account_t *a = c->accounts;
        c->accounts = a->next;
        if (a->backend->disconnect) a->backend->disconnect(a);
        free(a);
    }
    while (c->folders) { tri_folder_t *f = c->folders; c->folders = f->next; free(f); }
    for (int i = 0; i < c->nvframes; i++) free(c->vframes[i].buf);
    if (g_core == c) g_core = NULL;
    free(c);
}

static uint8_t *vframe_slot(tri_core *c, const char *acctkey, int which, int w, int h) {
    size_t need = (size_t)w * h * 4;
    int i = 0;
    for (; i < c->nvframes; i++)
        if (c->vframes[i].which == which && !strcmp(c->vframes[i].acctkey, acctkey)) break;
    if (i == c->nvframes) {
        if (c->nvframes >= (int)(sizeof c->vframes / sizeof c->vframes[0])) return NULL;
        c->nvframes++;
        snprintf(c->vframes[i].acctkey, sizeof c->vframes[i].acctkey, "%s", acctkey);
        c->vframes[i].which = which; c->vframes[i].buf = NULL; c->vframes[i].cap = 0; c->vframes[i].gen = 0;
    }
    if (c->vframes[i].cap < need) {
        uint8_t *nb = realloc(c->vframes[i].buf, need);
        if (!nb) return NULL;
        c->vframes[i].buf = nb; c->vframes[i].cap = need;
    }
    c->vframes[i].w = w; c->vframes[i].h = h;
    return c->vframes[i].buf;
}

void tri_call_video_publish(tri_core *c, const char *acctkey, int which, int w, int h, const uint8_t *rgba) {
    if (!c || !acctkey || w <= 0 || h <= 0 || !rgba) return;
    uint8_t *buf = vframe_slot(c, acctkey, which, w, h);
    if (!buf) return;
    memcpy(buf, rgba, (size_t)w * h * 4);
    tri_call_video_commit(c, acctkey, which);
}

uint8_t *tri_call_video_stage(tri_core *c, const char *acctkey, int which, int w, int h) {
    if (!c || !acctkey || w <= 0 || h <= 0) return NULL;
    return vframe_slot(c, acctkey, which, w, h);
}
void tri_call_video_commit(tri_core *c, const char *acctkey, int which) {
    if (!c || !acctkey) return;
    for (int i = 0; i < c->nvframes; i++)
        if (c->vframes[i].which == which && !strcmp(c->vframes[i].acctkey, acctkey)) { c->vframes[i].gen++; return; }
}

const uint8_t *tri_call_video_frame(tri_core *c, const char *acctkey, int which, int *w, int *h, unsigned *gen) {
    if (!c || !acctkey) return NULL;
    for (int i = 0; i < c->nvframes; i++)
        if (c->vframes[i].which == which && !strcmp(c->vframes[i].acctkey, acctkey) && c->vframes[i].buf) {
            if (w) *w = c->vframes[i].w; if (h) *h = c->vframes[i].h; if (gen) *gen = c->vframes[i].gen;
            return c->vframes[i].buf;
        }
    return NULL;
}

void tri_call_video_clear(tri_core *c, const char *acctkey, int which) {
    if (!c || !acctkey) return;
    for (int i = 0; i < c->nvframes; i++)
        if (!strcmp(c->vframes[i].acctkey, acctkey) && (which < 0 || c->vframes[i].which == which)) {
            free(c->vframes[i].buf); c->vframes[i].buf = NULL; c->vframes[i].cap = 0;
            c->vframes[i].w = c->vframes[i].h = 0; c->vframes[i].gen++;
        }
}

void tri_core_quit(tri_core *c) { if (c) c->running = 0; }

int tri_core_add_fd(tri_core *c, int fd, void (*cb)(void *, int), void *ud) {
    if (c->nfds >= TRI_MAX_FDS)
        return tri_set_error("cannot watch fd %d: core fd table full (max %d)", fd, TRI_MAX_FDS);
    c->fds[c->nfds++] = (fd_reg_t){ fd, cb, ud };
    return 0;
}
void tri_core_remove_fd(tri_core *c, int fd) {
    for (int i = 0; i < c->nfds; i++)
        if (c->fds[i].fd == fd) { c->fds[i] = c->fds[--c->nfds]; return; }
}

static void log_message(tri_core *c, const tri_event_t *ev);
static void match_rules(tri_core *c, const tri_event_t *ev);

void tri_emit(tri_core *c, const tri_event_t *ev) {
    tri_event_t e = *ev;
    if (e.timestamp == 0)
        e.timestamp = (long long)time(NULL);
    log_message(c, &e);
    match_rules(c, &e);
    if (c->on_event) c->on_event(c->ev_ud, &e);
}

void tri_core_step(tri_core *c, int timeout_ms) {
    fd_set r; FD_ZERO(&r); int mx = -1;
    for (account_t *a = c->accounts; a; a = a->next)
        if (a->fd >= 0) { FD_SET(a->fd, &r); if (a->fd > mx) mx = a->fd; }
    for (int i = 0; i < c->nfds; i++)
        { FD_SET(c->fds[i].fd, &r); if (c->fds[i].fd > mx) mx = c->fds[i].fd; }

    fd_set w; FD_ZERO(&w);
    for (account_t *a = c->accounts; a; a = a->next)
        if (a->fd >= 0 && a->want_write) { FD_SET(a->fd, &w); if (a->fd > mx) mx = a->fd; }

    int hmx = tri_http_fdset(c, &r, &w); if (hmx > mx) mx = hmx;

    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int n = select(mx + 1, &r, &w, NULL, &tv);
    if (n > 0) {
        for (account_t *a = c->accounts; a; a = a->next) {
            if (a->fd >= 0 && FD_ISSET(a->fd, &w) && a->backend->on_socket_writable)
                a->backend->on_socket_writable(a, a->fd);
            if (a->fd >= 0 && FD_ISSET(a->fd, &r) && a->backend->on_socket_readable)
                a->backend->on_socket_readable(a, a->fd);
        }
        for (int i = 0; i < c->nfds; i++)
            if (FD_ISSET(c->fds[i].fd, &r)) c->fds[i].cb(c->fds[i].ud, c->fds[i].fd);
        tri_http_service(c, &r, &w);
    }
    for (account_t *a = c->accounts; a; a = a->next)
        if (a->backend->tick) a->backend->tick(a);

    double t = now_s();
    for (account_t *a = c->accounts; a; a = a->next) {
        if (!a->want_connected || a->conn_state != TRI_CS_OFFLINE || a->fd >= 0) continue;
        if (a->next_retry_at == 0 || t < a->next_retry_at) continue;
        int n = a->retry_n++;
        double backoff = 1.0; for (int i = 0; i < n && backoff < 60.0; i++) backoff *= 2.0;
        if (backoff > 60.0) backoff = 60.0;
        a->next_retry_at = t + backoff;
        char m[96]; snprintf(m, sizeof m, "reconnecting (attempt %d)...", n + 1);
        tri_event_t ev = { TRI_EV_STATUS, a->key, "", m, NULL, 0 }; c->on_event(c->ev_ud, &ev);
        a->conn_state = TRI_CS_CONNECTING;
        if (a->backend->connect(a) != 0) {
            a->conn_state = TRI_CS_OFFLINE;
            tri_event_t er = { TRI_EV_ERROR, a->key, "", tri_last_error(), NULL, 0 }; c->on_event(c->ev_ud, &er);
        }
    }
}

void tri_core_run(tri_core *c) {
    c->running = 1;
    while (c->running) tri_core_step(c, 20);
}

account_t *tri_account_next(tri_core *c, account_t *prev) {
    return prev ? prev->next : c->accounts;
}

account_t *tri_account_find(tri_core *c, const char *name) {
    for (account_t *a = c->accounts; a; a = a->next)
        if (strcmp(a->name, name) == 0) return a;
    return NULL;
}

account_t *tri_account_find_by_key(tri_core *c, const char *key) {
    for (account_t *a = c->accounts; a; a = a->next)
        if (strcmp(a->key, key) == 0) return a;
    return NULL;
}

static account_t *account_new(tri_core *c, const char *backend, const char *name, const char *config) {
    const protocol_backend_t *b = NULL;
    for (size_t i = 0; i < sizeof REGISTRY / sizeof *REGISTRY; i++)
        if (strcmp(REGISTRY[i]->name, backend) == 0) { b = REGISTRY[i]; break; }
    if (!b) { tri_set_error("no backend named '%s' (known: echo, irc, mumble, xmpp)", backend); return NULL; }

    char key[96]; snprintf(key, sizeof key, "%s:%s", backend, name);
    if (tri_account_find_by_key(c, key)) {
        tri_set_error("a %s account named '%s' already exists", backend, name);
        return NULL;
    }
    account_t *a = calloc(1, sizeof *a);
    if (!a) { tri_set_error("out of memory allocating account '%s'", name); return NULL; }
    snprintf(a->name, sizeof a->name, "%s", name);
    snprintf(a->key, sizeof a->key, "%s", key);
    snprintf(a->config, sizeof a->config, "%s", config ? config : "");
    a->backend = b;
    a->fd = -1;
    a->core = c;
    a->folder = NULL;
    a->order = c->order_seq++;
    a->autoconnect = 1;
    { const char *q = config ? strchr(config, '?') : NULL;
      if (q && strstr(q, "insecure")) a->insecure = 1; }
    a->conn_state = TRI_CS_OFFLINE;
    a->next = c->accounts;
    c->accounts = a;
    return a;
}

account_t *tri_connect(tri_core *c, const char *backend, const char *name, const char *config) {
    account_t *a = account_new(c, backend, name, config);
    if (!a) return NULL;
    a->want_connected = 1;
    a->conn_state = TRI_CS_CONNECTING;
    if (a->backend->connect(a) != 0) {
        c->accounts = a->next;
        free(a);
        return NULL;
    }
    save_accounts(c);
    return a;
}

int tri_account_connect(account_t *a) {
    if (!a) return tri_set_error("no account");
    if (a->conn_state != TRI_CS_OFFLINE)
        return 0;
    a->want_connected = 1;
    a->retry_n = 0;
    a->next_retry_at = 0;
    a->conn_state = TRI_CS_CONNECTING;
    if (a->backend->connect(a) != 0) { a->conn_state = TRI_CS_OFFLINE; return -1; }
    return 0;
}

tri_conn_state tri_account_state(const account_t *a) { return a ? (tri_conn_state)a->conn_state : TRI_CS_OFFLINE; }
void tri_account_set_state(account_t *a, tri_conn_state s) {
    if (!a) return;
    a->conn_state = s;
    if (s == TRI_CS_ONLINE) { a->retry_n = 0; a->next_retry_at = 0; }
}
void tri_account_set_autoconnect(account_t *a, int on) { if (a) { a->autoconnect = on ? 1 : 0; save_accounts(a->core); } }
int  tri_account_autoconnect(const account_t *a) { return a ? a->autoconnect : 0; }
void tri_account_set_insecure(account_t *a, int on) { if (a) { a->insecure = on ? 1 : 0; save_accounts(a->core); } }
int  tri_account_insecure(const account_t *a) { return a ? a->insecure : 0; }

void tri_account_notify_down(account_t *a, const char *reason) {
    if (!a) return;
    a->fd = -1;
    a->conn_state = TRI_CS_OFFLINE;
    if (reason && reason[0]) { tri_event_t ev = { TRI_EV_ERROR, a->key, "", reason, NULL, 0 }; a->core->on_event(a->core->ev_ud, &ev); }
    if (a->want_connected && a->next_retry_at == 0) a->next_retry_at = now_s();
}

void tri_account_notify_failed(account_t *a, const char *reason) {
    if (!a) return;
    a->fd = -1;
    a->conn_state = TRI_CS_OFFLINE;
    a->want_connected = 0;
    a->next_retry_at = 0;
    if (reason && reason[0]) { tri_event_t ev = { TRI_EV_ERROR, a->key, "", reason, NULL, 0 }; a->core->on_event(a->core->ev_ud, &ev); }
}

int tri_send(account_t *a, const char *target, const char *body) {
    if (!a->backend->send_message)
        return tri_set_error("backend '%s' cannot send messages", a->backend->name);
    return a->backend->send_message(a, target, body);
}

int tri_typing(account_t *a, const char *target, int composing) {
    if (!a || !a->backend->typing || !target || !target[0]) return 0;
    a->backend->typing(a, target, composing);
    return 0;
}

int tri_call(account_t *a, const char *target, int action) {
    if (!a) return tri_set_error("no account");
    if (!a->backend->call) return tri_set_error("backend '%s' has no voice calling", a->backend->name);
    if (action == TRI_CALL_START && (!target || !target[0])) return tri_set_error("call: no target");
    return a->backend->call(a, target, action);
}
int tri_call_peers(account_t *a, const char *room, tri_call_peer_t *out, int cap) {
    if (!a || !room || !out || cap <= 0) return 0;
    if (!a->backend->call_peers) return 0;
    return a->backend->call_peers(a, room, out, cap);
}
int tri_call_peer_mute(account_t *a, const char *room, const char *full, int muted) {
    if (!a) return tri_set_error("no account");
    if (!a->backend->call_peer_mute) return tri_set_error("backend '%s' has no group calling", a->backend->name);
    return a->backend->call_peer_mute(a, room, full, muted);
}
void tri_account_set_faketyping(account_t *a, const char *target) {
    if (!a) return;
    snprintf(a->faketyping, sizeof a->faketyping, "%s", target ? target : "");
    if (a->faketyping[0]) tri_typing(a, a->faketyping, 1);
}
const char *tri_account_faketyping(const account_t *a) { return a ? a->faketyping : ""; }

int tri_send_raw(account_t *a, const char *line) {
    if (!a->backend->raw)
        return tri_set_error("backend '%s' has no raw-command path (that /command is IRC-only)", a->backend->name);
    return a->backend->raw(a, line);
}

int tri_send_action(account_t *a, const char *target, const char *body) {
    if (a->backend->send_action)
        return a->backend->send_action(a, target, body);
    if (!a->backend->send_message)
        return tri_set_error("backend '%s' cannot send messages", a->backend->name);
    char line[1100]; snprintf(line, sizeof line, "* %s", body);
    return a->backend->send_message(a, target, line);
}

int tri_upload(account_t *a, const char *target, const char *filepath) {
    if (!a->backend->upload)
        return tri_set_error("backend '%s' cannot upload files", a->backend->name);
    return a->backend->upload(a, target, filepath);
}

int tri_react(account_t *a, const char *target, const char *id, const char *emoji) {
    if (!a->backend->react) return tri_set_error("backend '%s' has no reactions", a->backend->name);
    if (!target || !target[0] || !id || !id[0]) return tri_set_error("react: target and message id required");
    return a->backend->react(a, target, id, emoji ? emoji : "");
}
int tri_correct(account_t *a, const char *target, const char *newbody) {
    if (!a->backend->correct) return tri_set_error("backend '%s' has no message correction", a->backend->name);
    if (!target || !target[0] || !newbody || !newbody[0]) return tri_set_error("correct: target and new text required");
    return a->backend->correct(a, target, newbody);
}

account_t *tri_upload_provider_next(tri_core *c, account_t *prev) {
    for (account_t *a = prev ? prev->next : c->accounts; a; a = a->next)
        if (a->backend->upload_relay && a->backend->upload_ready && a->backend->upload_ready(a))
            return a;
    return NULL;
}
account_t *tri_upload_provider(tri_core *c) { return tri_upload_provider_next(c, NULL); }

int tri_upload_cross(account_t *deliver_to, const char *target, const char *filepath, account_t *via) {
    if (!deliver_to || !target || !target[0] || !filepath) return tri_set_error("cross-upload: missing argument");
    if (!via || !via->backend->upload_relay)
        return tri_set_error("cross-upload: no linked account can host the file (need a connected XMPP account)");
    if (via->backend->upload_ready && !via->backend->upload_ready(via))
        return tri_set_error("cross-upload: %s has no file-upload service", via->key);
    return via->backend->upload_relay(via, filepath, deliver_to->key, target);
}

int tri_join(account_t *a, const char *target) {
    if (!a->backend->join)
        return tri_set_error("backend '%s' cannot join '%s'", a->backend->name, target);
    a->backend->join(a, target);
    return 0;
}

int tri_leave(account_t *a, const char *target) {
    if (!a->backend->leave)
        return tri_set_error("backend '%s' cannot leave '%s'", a->backend->name, target);
    a->backend->leave(a, target);
    return 0;
}

int tri_play(account_t *a, const char *path) {
    if (!a->backend->play_file)
        return tri_set_error("backend '%s' has no soundboard", a->backend->name);
    return a->backend->play_file(a, path);
}

int tri_mic(account_t *a, int on) {
    if (!a->backend->mic)
        return tri_set_error("backend '%s' has no microphone control", a->backend->name);
    return a->backend->mic(a, on);
}

int tri_record(account_t *a, const char *dir) {
    if (!a->backend->record)
        return tri_set_error("backend '%s' cannot record voice", a->backend->name);
    return a->backend->record(a, dir);
}

int tri_disconnect(account_t *a) {
    a->want_connected = 0;
    if (a->backend->disconnect) a->backend->disconnect(a);
    a->fd = -1;
    a->conn_state = TRI_CS_OFFLINE;
    a->next_retry_at = 0;
    return 0;
}

static int ignore_find(tri_core *c, const char *akey, const char *user) {
    for (int i = 0; i < c->nignores; i++)
        if (!strcmp(c->ignores[i].acctkey, akey) && !strcmp(c->ignores[i].user, user)) return i;
    return -1;
}
void tri_user_set_ignored(account_t *a, const char *user, int ignored) {
    if (!a || !user || !user[0]) return;
    tri_core *c = a->core;
    int i = ignore_find(c, a->key, user);
    if (ignored && i < 0 && c->nignores < (int)(sizeof c->ignores / sizeof *c->ignores)) {
        snprintf(c->ignores[c->nignores].acctkey, 96, "%s", a->key);
        snprintf(c->ignores[c->nignores].user, 128, "%s", user);
        c->nignores++;
    } else if (!ignored && i >= 0) {
        c->ignores[i] = c->ignores[--c->nignores];
    }
}
int tri_user_ignored(const account_t *a, const char *user) {
    if (!a || !user) return 0;
    return ignore_find(a->core, a->key, user) >= 0;
}

int tri_moderate(account_t *a, const char *channel, const char *user, const char *action, const char *arg) {
    if (!a->backend->moderate)
        return tri_set_error("backend '%s' has no moderation controls", a->backend->name);
    return a->backend->moderate(a, channel, user, action, arg);
}
int tri_omemo_own_fingerprint(account_t *a, char *out, size_t n) {
    if (!a->backend->omemo_own_fingerprint)
        return tri_set_error("backend '%s' has no OMEMO encryption", a->backend->name);
    return a->backend->omemo_own_fingerprint(a, out, n);
}
int tri_omemo_devices(account_t *a, const char *target, tri_omemo_device_t *out, int cap) {
    if (!a->backend->omemo_devices)
        return tri_set_error("backend '%s' has no OMEMO encryption", a->backend->name);
    return a->backend->omemo_devices(a, target, out, cap);
}
int tri_omemo_set_trust(account_t *a, const char *target, unsigned device_id, int trust) {
    if (!a->backend->omemo_set_trust)
        return tri_set_error("backend '%s' has no OMEMO encryption", a->backend->name);
    return a->backend->omemo_set_trust(a, target, device_id, trust);
}
int tri_user_info(account_t *a, const char *channel, const char *user) {
    if (!a->backend->user_info)
        return tri_set_error("backend '%s' cannot fetch user profiles", a->backend->name);
    return a->backend->user_info(a, channel, user);
}

void tri_account_remove(tri_core *c, account_t *a) {
    tri_roster_clear_account(a);

    for (int i = 0; i < c->nrefs; )
        if (!strcmp(c->refs[i].acctkey, a->key)) c->refs[i] = c->refs[--c->nrefs];
        else i++;
    save_folders(c);
    for (account_t **pp = &c->accounts; *pp; pp = &(*pp)->next)
        if (*pp == a) { *pp = a->next; break; }
    if (a->backend->disconnect) a->backend->disconnect(a);
    free(a);
    save_accounts(c);
}

static tri_folder_t *folder_by_id(tri_core *c, int id) {
    if (id == 0) return NULL;
    for (tri_folder_t *f = c->folders; f; f = f->next) if (f->id == id) return f;
    return NULL;
}

static int folder_in_subtree(tri_folder_t *x, tri_folder_t *f) {
    for (tri_folder_t *p = x; p; p = p->parent) if (p == f) return 1;
    return 0;
}

tri_folder_t *tri_folder_find(tri_core *c, const char *name, tri_folder_t *parent) {
    for (tri_folder_t *f = c->folders; f; f = f->next)
        if (f->parent == parent && !strcmp(f->name, name)) return f;
    return NULL;
}

const char *tri_folder_name(tri_folder_t *f) { return f ? f->name : ""; }

tri_folder_t *tri_folder_create(tri_core *c, const char *name, tri_folder_t *parent) {
    if (!name || !name[0]) { tri_set_error("folder name is required"); return NULL; }
    if (parent && parent->core != c) { tri_set_error("folder parent belongs to another core"); return NULL; }
    tri_folder_t *f = calloc(1, sizeof *f);
    if (!f) { tri_set_error("out of memory allocating folder '%s'", name); return NULL; }
    f->id = c->next_folder_id++;
    snprintf(f->name, sizeof f->name, "%s", name);
    f->parent = parent;
    f->order = c->order_seq++;
    f->core = c;
    f->next = c->folders;
    c->folders = f;
    save_folders(c);
    return f;
}

int tri_folder_rename(tri_folder_t *f, const char *new_name) {
    if (!new_name || !new_name[0]) return tri_set_error("folder name is required");
    snprintf(f->name, sizeof f->name, "%s", new_name);
    save_folders(f->core);
    return 0;
}

int tri_folder_move(tri_folder_t *f, tri_folder_t *new_parent) {
    if (folder_in_subtree(new_parent, f))
        return tri_set_error("cannot move folder '%s' into its own subtree", f->name);
    f->parent = new_parent;
    save_folders(f->core);
    return 0;
}

int tri_folder_delete(tri_folder_t *f, tri_folder_delete_mode_t mode) {
    tri_core *c = f->core;
    if (mode == TRI_FOLDER_DELETE_PROMOTE) {
        for (tri_folder_t *s = c->folders; s; s = s->next)
            if (s->parent == f) s->parent = f->parent;
        for (account_t *a = c->accounts; a; a = a->next)
            if (a->folder == f) a->folder = f->parent;
        for (int i = 0; i < c->nrefs; ) {
            if (c->refs[i].folder_id != f->id) { i++; continue; }
            if (!f->parent) { c->refs[i] = c->refs[--c->nrefs]; continue; }

            int dup = 0;
            for (int k = 0; k < c->nrefs; k++)
                if (k != i && c->refs[k].folder_id == f->parent->id &&
                    !strcmp(c->refs[k].acctkey, c->refs[i].acctkey) &&
                    !strcmp(c->refs[k].target, c->refs[i].target)) { dup = 1; break; }
            if (dup) c->refs[i] = c->refs[--c->nrefs];
            else { c->refs[i].folder_id = f->parent->id; i++; }
        }
    } else {
        for (account_t *a = c->accounts; a; a = a->next)
            if (a->folder && folder_in_subtree(a->folder, f)) a->folder = NULL;
        for (int i = 0; i < c->nrefs; ) {
            tri_folder_t *rf = folder_by_id(c, c->refs[i].folder_id);
            if (rf && folder_in_subtree(rf, f)) c->refs[i] = c->refs[--c->nrefs];
            else i++;
        }
        for (tri_folder_t **pp = &c->folders; *pp; )
            if (folder_in_subtree(*pp, f)) { tri_folder_t *dead = *pp; *pp = dead->next; free(dead); }
            else pp = &(*pp)->next;
    }

    if (mode == TRI_FOLDER_DELETE_PROMOTE)
        for (tri_folder_t **pp = &c->folders; *pp; pp = &(*pp)->next)
            if (*pp == f) { *pp = f->next; free(f); break; }
    save_folders(c);
    return 0;
}

static int collect_root(tri_core *c, tri_rootitem_t *items, int *orders, int max) {
    int n = 0;
    for (account_t *a = c->accounts; a; a = a->next)
        if (!a->folder && n < max) { items[n] = (tri_rootitem_t){ TRI_ROOTITEM_ACCOUNT, a }; orders[n] = a->order; n++; }
    for (tri_folder_t *f = c->folders; f; f = f->next)
        if (!f->parent && n < max) { items[n] = (tri_rootitem_t){ TRI_ROOTITEM_FOLDER, f }; orders[n] = f->order; n++; }
    for (int i = 1; i < n; i++) {
        tri_rootitem_t it = items[i]; int o = orders[i]; int j = i - 1;
        while (j >= 0 && orders[j] > o) { items[j+1] = items[j]; orders[j+1] = orders[j]; j--; }
        items[j+1] = it; orders[j+1] = o;
    }
    return n;
}

int tri_root_item_count(tri_core *c) {
    int n = 0;
    for (account_t *a = c->accounts; a; a = a->next) if (!a->folder) n++;
    for (tri_folder_t *f = c->folders; f; f = f->next) if (!f->parent) n++;
    return n;
}

tri_rootitem_t tri_root_item_get(tri_core *c, int index) {
    tri_rootitem_t items[512]; int orders[512];
    int n = collect_root(c, items, orders, 512);
    if (index < 0 || index >= n) return (tri_rootitem_t){ TRI_ROOTITEM_ACCOUNT, NULL };
    return items[index];
}

int tri_root_reorder(tri_core *c, int from, int to) {
    tri_rootitem_t items[512]; int orders[512];
    int n = collect_root(c, items, orders, 512);
    if (from < 0 || from >= n || to < 0 || to >= n) return tri_set_error("root reorder index out of range");
    tri_rootitem_t moved = items[from];
    if (from < to) { for (int i = from; i < to; i++) items[i] = items[i+1]; }
    else           { for (int i = from; i > to; i--) items[i] = items[i-1]; }
    items[to] = moved;

    for (int i = 0; i < n; i++) {
        if (items[i].kind == TRI_ROOTITEM_ACCOUNT) ((account_t *)items[i].ref)->order = orders[i];
        else ((tri_folder_t *)items[i].ref)->order = orders[i];
    }
    save_folders(c);
    return 0;
}

static int collect_folder(tri_folder_t *f, tri_folder_item_t *items, int *orders, int max) {
    tri_core *c = f->core; int n = 0;
    for (account_t *a = c->accounts; a; a = a->next)
        if (a->folder == f && n < max) {
            items[n] = (tri_folder_item_t){0}; items[n].kind = TRI_ITEM_ACCOUNT; items[n].account = a;
            orders[n] = a->order; n++;
        }
    for (tri_folder_t *s = c->folders; s; s = s->next)
        if (s->parent == f && n < max) {
            items[n] = (tri_folder_item_t){0}; items[n].kind = TRI_ITEM_FOLDER; items[n].folder = s;
            orders[n] = s->order; n++;
        }
    for (int i = 0; i < c->nrefs; i++)
        if (c->refs[i].folder_id == f->id && n < max) {
            items[n] = (tri_folder_item_t){0}; items[n].kind = TRI_ITEM_CHANNEL_REF;
            snprintf(items[n].acctkey, sizeof items[n].acctkey, "%s", c->refs[i].acctkey);
            snprintf(items[n].target, sizeof items[n].target, "%s", c->refs[i].target);
            orders[n] = c->refs[i].order; n++;
        }
    for (int i = 1; i < n; i++) {
        tri_folder_item_t it = items[i]; int o = orders[i]; int j = i - 1;
        while (j >= 0 && orders[j] > o) { items[j+1] = items[j]; orders[j+1] = orders[j]; j--; }
        items[j+1] = it; orders[j+1] = o;
    }
    return n;
}

int tri_folder_item_count(tri_folder_t *f) {
    tri_core *c = f->core; int n = 0;
    for (account_t *a = c->accounts; a; a = a->next) if (a->folder == f) n++;
    for (tri_folder_t *s = c->folders; s; s = s->next) if (s->parent == f) n++;
    for (int i = 0; i < c->nrefs; i++) if (c->refs[i].folder_id == f->id) n++;
    return n;
}

tri_folder_item_t tri_folder_item_get(tri_folder_t *f, int index) {
    tri_folder_item_t items[512]; int orders[512];
    int n = collect_folder(f, items, orders, 512);
    if (index < 0 || index >= n) { tri_folder_item_t z = {0}; z.kind = TRI_ITEM_ACCOUNT; return z; }
    return items[index];
}

int tri_account_move_to_folder(account_t *a, tri_folder_t *dest) {
    if (dest && dest->core != a->core) return tri_set_error("folder belongs to another core");
    a->folder = dest;
    save_folders(a->core);
    return 0;
}
tri_folder_t *tri_account_folder(account_t *a) { return a->folder; }

int tri_folder_ref_add(tri_folder_t *f, const char *acctkey, const char *target) {
    tri_core *c = f->core;
    for (int i = 0; i < c->nrefs; i++)
        if (c->refs[i].folder_id == f->id && !strcmp(c->refs[i].acctkey, acctkey) && !strcmp(c->refs[i].target, target))
            return 0;
    if (c->nrefs >= MAX_FOLDER_REFS) return tri_set_error("folder reference table full (max %d)", MAX_FOLDER_REFS);
    chanref_t *r = &c->refs[c->nrefs++];
    r->folder_id = f->id;
    snprintf(r->acctkey, sizeof r->acctkey, "%s", acctkey);
    snprintf(r->target, sizeof r->target, "%s", target);
    r->order = c->order_seq++;
    save_folders(c);
    return 0;
}
int tri_folder_ref_remove(tri_folder_t *f, const char *acctkey, const char *target) {
    tri_core *c = f->core;
    for (int i = 0; i < c->nrefs; )
        if (c->refs[i].folder_id == f->id && !strcmp(c->refs[i].acctkey, acctkey) && !strcmp(c->refs[i].target, target))
            c->refs[i] = c->refs[--c->nrefs];
        else i++;
    save_folders(c);
    return 0;
}
int tri_folder_ref_count_for(const char *acctkey, const char *target) {
    if (!g_core) return 0;
    int n = 0;
    for (int i = 0; i < g_core->nrefs; i++)
        if (!strcmp(g_core->refs[i].acctkey, acctkey) && !strcmp(g_core->refs[i].target, target)) n++;
    return n;
}
const char *tri_folder_ref_name_for(const char *acctkey, const char *target, int want) {
    if (!g_core) return NULL;
    int n = 0;
    for (int i = 0; i < g_core->nrefs; i++)
        if (!strcmp(g_core->refs[i].acctkey, acctkey) && !strcmp(g_core->refs[i].target, target)) {
            if (n == want) { tri_folder_t *f = folder_by_id(g_core, g_core->refs[i].folder_id); return f ? f->name : NULL; }
            n++;
        }
    return NULL;
}

static void roster_changed(account_t *a) {
    tri_event_t ev = { TRI_EV_ROSTER, tri_account_key(a), NULL, "", NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

void tri_roster_upsert(account_t *a, const char *channel, const char *user, int talking) {
    tri_core *c = a->core; const char *key = a->key;
    for (int i = 0; i < c->nroster; i++)
        if (!strcmp(c->roster[i].acctkey, key) && !strcmp(c->roster[i].channel, channel) && !strcmp(c->roster[i].user, user)) {
            int changed = c->roster[i].talking != talking;
            c->roster[i].talking = talking;
            if (changed) roster_changed(a);
            return;
        }
    if (c->nroster >= MAX_ROSTER) return;
    rentry_t *r = &c->roster[c->nroster++];
    snprintf(r->acctkey, sizeof r->acctkey, "%s", key);
    snprintf(r->channel, sizeof r->channel, "%s", channel);
    snprintf(r->user, sizeof r->user, "%s", user);
    r->talking = talking;
    roster_changed(a);
}
void tri_roster_remove(account_t *a, const char *user) {
    tri_core *c = a->core; int hit = 0;
    for (int i = 0; i < c->nroster; )
        if (!strcmp(c->roster[i].acctkey, a->key) && !strcmp(c->roster[i].user, user)) { c->roster[i] = c->roster[--c->nroster]; hit = 1; }
        else i++;
    if (hit) roster_changed(a);
}
void tri_roster_remove_from(account_t *a, const char *channel, const char *user) {
    tri_core *c = a->core; int hit = 0;
    for (int i = 0; i < c->nroster; )
        if (!strcmp(c->roster[i].acctkey, a->key) && !strcmp(c->roster[i].channel, channel) && !strcmp(c->roster[i].user, user))
            { c->roster[i] = c->roster[--c->nroster]; hit = 1; }
        else i++;
    if (hit) roster_changed(a);
}
void tri_roster_clear_account(account_t *a) {
    tri_core *c = a->core;
    for (int i = 0; i < c->nroster; )
        if (!strcmp(c->roster[i].acctkey, a->key)) c->roster[i] = c->roster[--c->nroster];
        else i++;
}
int tri_roster_count(tri_core *c) { return c->nroster; }
int tri_roster_get(tri_core *c, int i, const char **acctkey, const char **channel, const char **user, int *talking) {
    if (i < 0 || i >= c->nroster) return 0;
    *acctkey = c->roster[i].acctkey; *channel = c->roster[i].channel; *user = c->roster[i].user; *talking = c->roster[i].talking;
    return 1;
}

#define CT_KEEP ((unsigned)-1)
void tri_chantree_upsert(account_t *a, unsigned id, unsigned parent, const char *name) {
    tri_core *c = a->core; const char *key = a->key;
    cnode_t *n = NULL;
    for (int i = 0; i < c->nchantree; i++)
        if (c->chantree[i].id == id && !strcmp(c->chantree[i].acctkey, key)) { n = &c->chantree[i]; break; }
    if (!n) {
        if (c->nchantree >= MAX_CHANTREE) return;
        n = &c->chantree[c->nchantree++];
        snprintf(n->acctkey, sizeof n->acctkey, "%s", key);
        n->id = id; n->parent = 0; n->name[0] = '\0';
    }
    if (parent != CT_KEEP) n->parent = parent;
    if (name) snprintf(n->name, sizeof n->name, "%s", name);
    roster_changed(a);
}
void tri_chantree_remove(account_t *a, unsigned id) {
    tri_core *c = a->core;
    for (int i = 0; i < c->nchantree; i++)
        if (c->chantree[i].id == id && !strcmp(c->chantree[i].acctkey, a->key)) {
            c->chantree[i] = c->chantree[--c->nchantree]; roster_changed(a); return;
        }
}
void tri_chantree_clear_account(account_t *a) {
    tri_core *c = a->core; int hit = 0;
    for (int i = 0; i < c->nchantree; )
        if (!strcmp(c->chantree[i].acctkey, a->key)) { c->chantree[i] = c->chantree[--c->nchantree]; hit = 1; }
        else i++;
    if (hit) roster_changed(a);
}
int tri_chantree_count(tri_core *c) { return c->nchantree; }
int tri_chantree_get(tri_core *c, int i, const char **acctkey, unsigned *id, unsigned *parent, const char **name) {
    if (i < 0 || i >= c->nchantree) return 0;
    *acctkey = c->chantree[i].acctkey; *id = c->chantree[i].id; *parent = c->chantree[i].parent; *name = c->chantree[i].name;
    return 1;
}

static int chan_find(tri_core *c, const char *akey, const char *tgt) {
    for (int i = 0; i < c->nchans; i++)
        if (!strcmp(c->chans[i].acctkey, akey) && !strcmp(c->chans[i].target, tgt)) return i;
    return -1;
}
static int chan_get_or_add(tri_core *c, const char *akey, const char *tgt) {
    int i = chan_find(c, akey, tgt);
    if (i >= 0) return i;
    if (c->nchans >= (int)(sizeof c->chans / sizeof *c->chans)) return -1;
    i = c->nchans++;
    snprintf(c->chans[i].acctkey, 96, "%s", akey);
    snprintf(c->chans[i].target, 128, "%s", tgt);
    c->chans[i].nick[0] = '\0'; c->chans[i].logmode = -1;
    c->chans[i].encrypt = 0;
    c->chans[i].notify = 0;
    c->chans[i].member = 0;
    return i;
}

static int chan_log_effective(tri_core *c, const char *akey, const char *tgt) {
    int i = chan_find(c, akey, tgt);
    if (i >= 0 && c->chans[i].logmode >= 0) return c->chans[i].logmode;
    int j = chan_find(c, akey, "");
    if (j >= 0 && c->chans[j].logmode >= 0) return c->chans[j].logmode;
    return c->log_global;
}

void tri_channel_set_nick(account_t *a, const char *target, const char *nick) {
    int i = chan_get_or_add(a->core, a->key, target); if (i < 0) return;
    snprintf(a->core->chans[i].nick, 64, "%s", nick ? nick : "");
    save_channels(a->core);
}
const char *tri_channel_nick(account_t *a, const char *target) {
    int i = chan_find(a->core, a->key, target);
    return (i >= 0) ? a->core->chans[i].nick : "";
}

void tri_channel_set_member(account_t *a, const char *target, int on) {
    if (!a || !target || !target[0]) return;
    int i = chan_get_or_add(a->core, a->key, target); if (i < 0) return;
    signed char v = on ? 1 : 0;
    if (a->core->chans[i].member == v) return;
    a->core->chans[i].member = v;
    save_channels(a->core);
}

void tri_channel_member_list(account_t *a, char *out, size_t osz) {
    if (!out || osz == 0) return;
    out[0] = '\0';
    if (!a) return;
    size_t n = 0;
    for (int i = 0; i < a->core->nchans; i++) {
        if (a->core->chans[i].member != 1) continue;
        if (strcmp(a->core->chans[i].acctkey, a->key)) continue;
        if (!a->core->chans[i].target[0]) continue;
        n += snprintf(out + n, n < osz ? osz - n : 0, "%s%s", n ? "," : "", a->core->chans[i].target);
        if (n >= osz) { out[osz - 1] = '\0'; break; }
    }
}
int tri_target_is_group(account_t *a, const char *target) {
    if (!a || !target || !target[0]) return 0;
    if (a->backend->is_group) return a->backend->is_group(a, target);
    return strchr("#&+!", target[0]) != NULL;
}
void tri_channel_set_log(account_t *a, const char *target, int mode) {
    int i = chan_get_or_add(a->core, a->key, target); if (i < 0) return;
    a->core->chans[i].logmode = (signed char)mode;
    save_channels(a->core);
}
int tri_channel_log(account_t *a, const char *target) { return chan_log_effective(a->core, a->key, target); }
void tri_channel_set_encrypt(account_t *a, const char *target, int on) {
    int i = chan_get_or_add(a->core, a->key, target); if (i < 0) return;
    a->core->chans[i].encrypt = on ? 1 : 0;
}
int tri_channel_encrypt(account_t *a, const char *target) {
    int i = chan_find(a->core, a->key, target);
    return (i >= 0) ? a->core->chans[i].encrypt : 0;
}

static int chan_notify(tri_core *c, const char *akey, const char *tgt) {
    int i = chan_find(c, akey, tgt);
    return (i >= 0) ? c->chans[i].notify : 0;
}
void tri_channel_set_notify(account_t *a, const char *target, int level) {
    int i = chan_get_or_add(a->core, a->key, target); if (i < 0) return;
    a->core->chans[i].notify = (signed char)(level < 0 ? 0 : level > 2 ? 2 : level);
    save_channels(a->core);
}
int tri_channel_notify(account_t *a, const char *target) { return chan_notify(a->core, a->key, target); }
void tri_account_set_log(account_t *a, int mode) {
    int i = chan_get_or_add(a->core, a->key, ""); if (i < 0) return;
    a->core->chans[i].logmode = (signed char)mode;
    save_channels(a->core);
}
int tri_account_log(account_t *a) {
    int i = chan_find(a->core, a->key, "");
    return (i >= 0) ? a->core->chans[i].logmode : -1;
}
void tri_log_set_global(tri_core *c, int on) { c->log_global = on ? 1 : 0; save_channels(c); }
int  tri_log_global(tri_core *c) { return c->log_global; }

static int ci_contains(const char *hay, const char *needle) {
    if (!needle[0]) return 0;
    for (; *hay; hay++) {
        size_t i = 0;
        while (hay[i] && needle[i] && tolower((unsigned char)hay[i]) == tolower((unsigned char)needle[i])) i++;
        if (!needle[i]) return 1;
    }
    return 0;
}

static void fs_safe(const char *s, char *out, size_t n) {
    size_t i = 0;
    for (; s[i] && i < n - 1; i++) { char ch = s[i]; out[i] = (ch == '/' || ch == '\\' || (unsigned char)ch < 0x20) ? '_' : ch; }
    out[i] = '\0';
}

static void json_esc(const char *s, char *out, size_t n) {
    size_t o = 0;
    for (; *s && o + 2 < n; s++) {
        unsigned char ch = *s;
        if (ch == '"' || ch == '\\') { out[o++] = '\\'; out[o++] = ch; }
        else if (ch < 0x20)          { o += snprintf(out + o, n - o, "\\u%04x", ch); }
        else                          out[o++] = ch;
    }
    out[o] = '\0';
}

static void json_unesc(const char *s, size_t len, char *out, size_t n) {
    size_t o = 0;
    for (size_t i = 0; i < len && o + 1 < n; i++) {
        if (s[i] == '\\' && i + 1 < len) {
            char e = s[++i];
            if      (e == 'n') out[o++] = '\n';
            else if (e == 't') out[o++] = '\t';
            else if (e == 'r') out[o++] = '\r';
            else if (e == 'u' && i + 4 < len) {
                int v = 0;
                for (int k = 0; k < 4; k++) { char h = s[i + 1 + k]; v = v * 16 + (h <= '9' ? h - '0' : (h | 32) - 'a' + 10); }
                i += 4;
                if (v < 0x80)        { out[o++] = (char)v; }
                else if (v < 0x800)  { if (o + 2 < n) { out[o++] = (char)(0xC0 | (v >> 6)); out[o++] = (char)(0x80 | (v & 0x3F)); } }
                else                 { if (o + 3 < n) { out[o++] = (char)(0xE0 | (v >> 12)); out[o++] = (char)(0x80 | ((v >> 6) & 0x3F)); out[o++] = (char)(0x80 | (v & 0x3F)); } }
            } else out[o++] = e;
        } else out[o++] = s[i];
    }
    out[o] = '\0';
}

static int json_str_field(const char *line, const char *key, const char **vs) {
    char pat[40]; snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(line, pat); if (!p) return -1;
    p += strlen(pat);
    const char *q = p;
    while (*q) { if (*q == '\\' && q[1]) q += 2; else if (*q == '"') break; else q++; }
    if (*q != '"') return -1;
    *vs = p; return (int)(q - p);
}

#define BACKLOG_MAX 200

static int log_dir_for(tri_core *c, const char *acctkey, char *out, size_t n) {
    if (!c->store[0]) return -1;
    char base[520]; snprintf(base, sizeof base, "%s", c->store);
    char *sl = strrchr(base, '/'); if (sl) *sl = '\0'; else base[0] = '\0';
    char safek[96]; fs_safe(acctkey, safek, sizeof safek);
    snprintf(out, n, "%s/logs/%s", base[0] ? base : ".", safek);
    mkdir_p(out);
    return 0;
}

static void jsonl_append(const char *path, long long ts, const char *nick, const char *text) {
    FILE *f = fopen(path, "a"); if (!f) return;
    char et[1400], en[160]; json_esc(text ? text : "", et, sizeof et); json_esc(nick ? nick : "", en, sizeof en);
    fprintf(f, "{\"ts\":%lld,\"nick\":\"%s\",\"text\":\"%s\"}\n", ts, en, et);
    fclose(f);
}

static void backlog_trim(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= (off_t)(BACKLOG_MAX * 2 * 300)) return;
    FILE *f = fopen(path, "rb"); if (!f) return;
    long sz = st.st_size;
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    size_t rd = fread(buf, 1, (size_t)sz, f); fclose(f); buf[rd] = '\0';
    int nl = 0; for (size_t i = 0; i < rd; i++) if (buf[i] == '\n') nl++;
    if (nl <= BACKLOG_MAX) { free(buf); return; }
    int skip = nl - BACKLOG_MAX, seen = 0; size_t start = 0;
    for (size_t i = 0; i < rd && seen < skip; i++) if (buf[i] == '\n') { seen++; start = i + 1; }
    FILE *o = fopen(path, "wb");
    if (o) { fwrite(buf + start, 1, rd - start, o); fclose(o); }
    free(buf);
}

static void log_message(tri_core *c, const tri_event_t *ev) {
    if (!c->store[0] || ev->kind != TRI_EV_MESSAGE || ev->history) return;
    if (!ev->account || ev->account[0] == '*' || !ev->target || !ev->target[0]) return;
    char dir[600]; if (log_dir_for(c, ev->account, dir, sizeof dir) != 0) return;
    char safet[128]; fs_safe(ev->target, safet, sizeof safet);
    char rpath[760]; snprintf(rpath, sizeof rpath, "%s/%s.recent", dir, safet);
    jsonl_append(rpath, ev->timestamp, ev->nick, ev->text);
    backlog_trim(rpath);
    if (chan_log_effective(c, ev->account, ev->target)) {
        char apath[760]; snprintf(apath, sizeof apath, "%s/%s.jsonl", dir, safet);
        jsonl_append(apath, ev->timestamp, ev->nick, ev->text);
    }
}

int tri_history_replay(account_t *a, const char *target, int max) {
    if (!a || !target || !target[0]) return tri_set_error("history: account and target required");
    tri_core *c = a->core;
    if (!c->store[0]) return tri_set_error("history: no message store configured");
    if (!c->on_event) return 0;
    if (max <= 0 || max > 5000) max = BACKLOG_MAX;
    char dir[600]; if (log_dir_for(c, a->key, dir, sizeof dir) != 0) return tri_set_error("history: no log directory");
    char safet[128]; fs_safe(target, safet, sizeof safet);
    char path[760]; snprintf(path, sizeof path, "%s/%s.jsonl", dir, safet);
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(path, sizeof path, "%s/%s.recent", dir, safet); f = fopen(path, "rb"); }
    if (!f) return 0;
    long cap = (long)max * 2048; if (cap < 65536) cap = 65536;
    fseek(f, 0, SEEK_END); long sz = ftell(f);
    long start = sz > cap ? sz - cap : 0;
    fseek(f, start, SEEK_SET);
    char *buf = malloc((size_t)(sz - start) + 1);
    if (!buf) { fclose(f); return tri_set_error("history: out of memory"); }
    size_t rd = fread(buf, 1, (size_t)(sz - start), f); fclose(f); buf[rd] = '\0';
    char *p = buf;
    if (start > 0) { char *nlp = strchr(buf, '\n'); p = nlp ? nlp + 1 : buf + rd; }
    const char **lines = malloc(sizeof(char *) * (size_t)max);
    if (!lines) { free(buf); return tri_set_error("history: out of memory"); }
    int head = 0, cnt = 0;
    for (char *line = p; *line; ) {
        char *e = strchr(line, '\n'); if (!e) break;
        *e = '\0';
        lines[head] = line; head = (head + 1) % max; if (cnt < max) cnt++;
        line = e + 1;
    }
    int first = (head - cnt + max) % max, replayed = 0;
    for (int i = 0; i < cnt; i++) {
        const char *ln = lines[(first + i) % max];
        const char *ts = strstr(ln, "\"ts\":");
        const char *nv, *tv; int nl2 = json_str_field(ln, "nick", &nv), tl = json_str_field(ln, "text", &tv);
        if (tl < 0) continue;
        char nick[160] = "", text[1500];
        if (nl2 >= 0) json_unesc(nv, (size_t)nl2, nick, sizeof nick);
        json_unesc(tv, (size_t)tl, text, sizeof text);
        tri_event_t ev = { TRI_EV_MESSAGE, a->key, target, text, nick[0] ? nick : NULL,
                           ts ? atoll(ts + 5) : 0, 0, 1 };
        c->on_event(c->ev_ud, &ev);
        replayed++;
    }
    free(lines); free(buf);
    return replayed;
}

static void account_self_nick(account_t *a, char *out, size_t n) {
    out[0] = '\0';
    const char *p = strstr(a->config, "://");
    if (!p) return;
    p += 3;
    const char *at = strchr(p, '@');
    if (!at) return;
    size_t len = 0;
    for (const char *q = p; q < at && *q != ':' && len + 1 < n; q++) out[len++] = *q;
    out[len] = '\0';
}

static void match_rules(tri_core *c, const tri_event_t *ev) {
    if (ev->kind != TRI_EV_MESSAGE || !ev->account || ev->account[0] == '*' || !ev->text) return;
    account_t *self = tri_account_find_by_key(c, ev->account);
    char mynick[64] = ""; if (self) account_self_nick(self, mynick, sizeof mynick);
    if (mynick[0] && ev->nick && !strcasecmp(ev->nick, mynick)) return;
    if (ev->target && chan_notify(c, ev->account, ev->target) == 2) return;

    int hit = mynick[0] && ci_contains(ev->text, mynick);
    for (int i = 0; i < c->nrules && !hit; i++) {
        if (c->rules[i].acctkey[0] && strcmp(c->rules[i].acctkey, ev->account)) continue;
        if (c->rules[i].target[0] && (!ev->target || strcmp(c->rules[i].target, ev->target))) continue;
        if (ci_contains(ev->text, c->rules[i].pattern) || (ev->nick && ci_contains(ev->nick, c->rules[i].pattern))) hit = 1;
    }
    if (!hit) return;

    if (c->ninbox < (int)(sizeof c->inbox / sizeof *c->inbox)) {
        int k = c->ninbox++;
        snprintf(c->inbox[k].acctkey, 96, "%s", ev->account);
        snprintf(c->inbox[k].target, 128, "%s", ev->target ? ev->target : "");
        snprintf(c->inbox[k].nick, 64, "%s", ev->nick ? ev->nick : "");
        snprintf(c->inbox[k].text, 400, "%s", ev->text);
        c->inbox[k].ts = ev->timestamp;
    }
    char m[700]; snprintf(m, sizeof m, "[%s%s%s] <%s> %s", ev->account, ev->target ? "/" : "",
                          ev->target ? ev->target : "", ev->nick ? ev->nick : "", ev->text);
    tri_event_t al = { TRI_EV_STATUS, "*:alert", ev->target, m, NULL, ev->timestamp };
    if (c->on_event) c->on_event(c->ev_ud, &al);
}

int tri_rule_add(tri_core *c, const char *pattern, const char *acctkey, const char *target) {
    if (!pattern || !pattern[0]) return tri_set_error("alert pattern is required");
    if (c->nrules >= (int)(sizeof c->rules / sizeof *c->rules)) return tri_set_error("alert rule table full (max %d)", (int)(sizeof c->rules / sizeof *c->rules));
    int i = c->nrules++;
    snprintf(c->rules[i].pattern, 128, "%s", pattern);
    snprintf(c->rules[i].acctkey, 96, "%s", acctkey ? acctkey : "");
    snprintf(c->rules[i].target, 128, "%s", target ? target : "");
    save_rules(c);
    return 0;
}
void tri_rule_remove(tri_core *c, int i) { if (i >= 0 && i < c->nrules) { c->rules[i] = c->rules[--c->nrules]; save_rules(c); } }
int  tri_rule_count(tri_core *c) { return c->nrules; }
int  tri_rule_get(tri_core *c, int i, const char **pattern, const char **acctkey, const char **target) {
    if (i < 0 || i >= c->nrules) return 0;
    *pattern = c->rules[i].pattern; *acctkey = c->rules[i].acctkey; *target = c->rules[i].target;
    return 1;
}

int  tri_inbox_count(tri_core *c) { return c->ninbox; }
void tri_inbox_clear(tri_core *c) { c->ninbox = 0; }
int  tri_inbox_get(tri_core *c, int i, const char **acctkey, const char **target, const char **nick, const char **text, long long *ts) {
    if (i < 0 || i >= c->ninbox) return 0;
    *acctkey = c->inbox[i].acctkey; *target = c->inbox[i].target; *nick = c->inbox[i].nick; *text = c->inbox[i].text; *ts = c->inbox[i].ts;
    return 1;
}

static void save_saved(tri_core *c) {
    if (!c->sstore[0]) return;
    FILE *f = fopen(c->sstore, "w");
    if (!f) { save_failed(c, c->sstore); return; }
    for (int i = 0; i < c->nsaved; i++) {
        char txt[400]; snprintf(txt, sizeof txt, "%s", c->saved[i].text);
        for (char *p = txt; *p; p++) if (*p == '\t' || *p == '\n') *p = ' ';
        fprintf(f, "%s\t%s\t%lld\t%s\t%s\n", c->saved[i].acctkey, c->saved[i].target[0] ? c->saved[i].target : "-",
                c->saved[i].ts, c->saved[i].nick[0] ? c->saved[i].nick : "-", txt);
    }
    fclose(f);
    chmod(c->sstore, 0600);
}
static void load_saved(tri_core *c) {
    if (!c->sstore[0]) return;
    FILE *f = fopen(c->sstore, "r");
    if (!f) return;
    char line[700];
    while (fgets(line, sizeof line, f) && c->nsaved < (int)(sizeof c->saved / sizeof *c->saved)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *ak = strtok(line, "\t"), *tg = strtok(NULL, "\t"), *ts = strtok(NULL, "\t"),
             *nk = strtok(NULL, "\t"), *tx = strtok(NULL, "");
        if (!ak || !tg || !ts || !nk || !tx) continue;
        int i = c->nsaved++;
        snprintf(c->saved[i].acctkey, 96, "%s", ak);
        snprintf(c->saved[i].target, 128, "%s", strcmp(tg, "-") ? tg : "");
        c->saved[i].ts = atoll(ts);
        snprintf(c->saved[i].nick, 64, "%s", strcmp(nk, "-") ? nk : "");
        snprintf(c->saved[i].text, 400, "%s", tx);
    }
    fclose(f);
}
int tri_saved_add(tri_core *c, const char *acctkey, const char *target, const char *nick, const char *text, long long ts) {
    if (!text || !text[0]) return tri_set_error("nothing to save");
    if (c->nsaved >= (int)(sizeof c->saved / sizeof *c->saved)) return tri_set_error("saved-message store full (max %d)", (int)(sizeof c->saved / sizeof *c->saved));
    int i = c->nsaved++;
    snprintf(c->saved[i].acctkey, 96, "%s", acctkey ? acctkey : "");
    snprintf(c->saved[i].target, 128, "%s", target ? target : "");
    snprintf(c->saved[i].nick, 64, "%s", nick ? nick : "");
    snprintf(c->saved[i].text, 400, "%s", text);
    c->saved[i].ts = ts;
    save_saved(c);
    return 0;
}
void tri_saved_remove(tri_core *c, int i) { if (i >= 0 && i < c->nsaved) { memmove(&c->saved[i], &c->saved[i+1], (c->nsaved - i - 1) * sizeof *c->saved); c->nsaved--; save_saved(c); } }
int  tri_saved_count(tri_core *c) { return c->nsaved; }
int  tri_saved_get(tri_core *c, int i, const char **acctkey, const char **target, const char **nick, const char **text, long long *ts) {
    if (i < 0 || i >= c->nsaved) return 0;
    *acctkey = c->saved[i].acctkey; *target = c->saved[i].target; *nick = c->saved[i].nick; *text = c->saved[i].text; *ts = c->saved[i].ts;
    return 1;
}

static void save_channels(tri_core *c) {
    if (!c->cstore[0]) return;
    FILE *f = fopen(c->cstore, "w");
    if (!f) { save_failed(c, c->cstore); return; }
    fprintf(f, "G\t%d\n", c->log_global);
    for (int i = 0; i < c->nchans; i++)
        fprintf(f, "C\t%s\t%s\t%d\t%d\t%d\t%s\n", c->chans[i].acctkey, c->chans[i].target[0] ? c->chans[i].target : "-",
                c->chans[i].logmode, c->chans[i].notify, c->chans[i].member, c->chans[i].nick[0] ? c->chans[i].nick : "-");
    fclose(f);
    chmod(c->cstore, 0600);
}
static void load_channels(tri_core *c) {
    if (!c->cstore[0]) return;
    FILE *f = fopen(c->cstore, "r");
    if (!f) return;
    char line[400];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == 'G') { char *g = line + 1; while (*g == '\t') g++; c->log_global = atoi(g); }
        else if (line[0] == 'C' && c->nchans < (int)(sizeof c->chans / sizeof *c->chans)) {
            strtok(line, "\t");
            char *ak = strtok(NULL, "\t"), *tg = strtok(NULL, "\t"), *lm = strtok(NULL, "\t");

            char *t4 = strtok(NULL, "\t"), *t5 = strtok(NULL, "\t"), *t6 = strtok(NULL, "\t");
            if (!ak || !tg || !lm) continue;
            int i = c->nchans++;
            snprintf(c->chans[i].acctkey, 96, "%s", ak);
            snprintf(c->chans[i].target, 128, "%s", strcmp(tg, "-") ? tg : "");
            c->chans[i].logmode = (signed char)atoi(lm);
            const char *nk;
            if (t6)      { c->chans[i].notify = (signed char)atoi(t4); c->chans[i].member = (signed char)atoi(t5); nk = strcmp(t6, "-") ? t6 : ""; }
            else if (t5) { c->chans[i].notify = (signed char)atoi(t4); c->chans[i].member = 0; nk = strcmp(t5, "-") ? t5 : ""; }
            else         { c->chans[i].notify = 0; c->chans[i].member = 0; nk = t4 ? t4 : ""; }
            snprintf(c->chans[i].nick, 64, "%s", nk);
        }
    }
    fclose(f);
}
static void save_rules(tri_core *c) {
    if (!c->rstore[0]) return;
    FILE *f = fopen(c->rstore, "w");
    if (!f) { save_failed(c, c->rstore); return; }
    for (int i = 0; i < c->nrules; i++)
        fprintf(f, "%s\t%s\t%s\n", c->rules[i].acctkey[0] ? c->rules[i].acctkey : "-",
                c->rules[i].target[0] ? c->rules[i].target : "-", c->rules[i].pattern);
    fclose(f);
    chmod(c->rstore, 0600);
}
static void load_rules(tri_core *c) {
    if (!c->rstore[0]) return;
    FILE *f = fopen(c->rstore, "r");
    if (!f) return;
    char line[400];
    while (fgets(line, sizeof line, f) && c->nrules < (int)(sizeof c->rules / sizeof *c->rules)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *ak = strtok(line, "\t"), *tg = strtok(NULL, "\t"), *pat = strtok(NULL, "");
        if (!ak || !tg || !pat) continue;
        int i = c->nrules++;
        snprintf(c->rules[i].pattern, 128, "%s", pat);
        snprintf(c->rules[i].acctkey, 96, "%s", strcmp(ak, "-") ? ak : "");
        snprintf(c->rules[i].target, 128, "%s", strcmp(tg, "-") ? tg : "");
    }
    fclose(f);
}

#ifdef TRI_PULSE
#include <pulse/simple.h>
#include <pulse/error.h>
#endif
#include <pthread.h>

#define AUDIO_RATE       48000
#define AUDIO_RING_CAP   (AUDIO_RATE)
#define AUDIO_WR_CHUNK   4800

struct tri_audio_sink {
#ifdef TRI_PULSE
    pa_simple *pa;
#endif
    FILE *pipe;
    int16_t  ring[AUDIO_RING_CAP];
    size_t   head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    pthread_t       thread;
    int      threaded;
    int      stop;
};

static int have_cmd(const char *cmd) { char b[64]; snprintf(b, sizeof b, "command -v %s >/dev/null 2>&1", cmd); return system(b) == 0; }

static int getenv_of_pid(const char *pid, const char *key, char *out, size_t n) {
    char path[300]; snprintf(path, sizeof path, "/proc/%s/environ", pid);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char buf[16384]; size_t len = fread(buf, 1, sizeof buf - 1, f); fclose(f);
    buf[len] = '\0';
    size_t klen = strlen(key), i = 0;
    while (i < len) {
        char *ent = buf + i; size_t elen = strlen(ent);
        if (elen > klen && !strncmp(ent, key, klen) && ent[klen] == '=') { snprintf(out, n, "%s", ent + klen + 1); return 1; }
        i += elen + 1;
    }
    return 0;
}

static void adopt_user_audio(void) {
    if (geteuid() != 0) return;
    if (getenv("PULSE_SERVER") || getenv("XDG_RUNTIME_DIR")) return;
    long want = -1; const char *su = getenv("SUDO_UID"); if (su) want = atol(su);
    DIR *d = opendir("/proc"); if (!d) return;
    char chosen[16] = ""; uid_t cuid = 0; char tmp[512];
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        char pp[300]; snprintf(pp, sizeof pp, "/proc/%s", e->d_name);
        struct stat st; if (stat(pp, &st) != 0 || st.st_uid == 0) continue;
        if (want >= 0 && (long)st.st_uid != want) continue;
        if (getenv_of_pid(e->d_name, "XDG_RUNTIME_DIR", tmp, sizeof tmp) ||
            getenv_of_pid(e->d_name, "PULSE_SERVER", tmp, sizeof tmp) ||
            getenv_of_pid(e->d_name, "PULSE_RUNTIME_PATH", tmp, sizeof tmp)) {
            snprintf(chosen, sizeof chosen, "%s", e->d_name); cuid = st.st_uid; break;
        }
    }
    closedir(d);
    if (!chosen[0]) return;
    const char *vars[] = { "XDG_RUNTIME_DIR", "PULSE_SERVER", "PULSE_RUNTIME_PATH", "PULSE_COOKIE", "DBUS_SESSION_BUS_ADDRESS", NULL };
    for (int i = 0; vars[i]; i++) { char v[512]; if (getenv_of_pid(chosen, vars[i], v, sizeof v)) setenv(vars[i], v, 1); }
    if (!getenv("PULSE_COOKIE")) {
        struct passwd *pw = getpwuid(cuid);
        if (pw) { char ck[300]; snprintf(ck, sizeof ck, "%s/.config/pulse/cookie", pw->pw_dir); if (access(ck, R_OK) == 0) setenv("PULSE_COOKIE", ck, 1); }
    }
}

static void audio_name_safe(const char *in, char *out, size_t n) {
    size_t o = 0;
    const char *p = (in && in[0]) ? in : "voice";
    for (; *p && o + 1 < n; p++) {
        char c = *p;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                 || c == ' ' || c == '-' || c == '_' || c == '.' || c == ':';
        out[o++] = ok ? c : '_';
    }
    out[o] = '\0';
    if (!o) snprintf(out, n, "voice");
}
static void build_cmd(const char *m, const char *dev, const char *name, char *out, size_t n) {
    out[0] = '\0';
    char nm[96]; audio_name_safe(name, nm, sizeof nm);
    if (!strcmp(m, "pulse"))         snprintf(out, n, "pacat --format=s16le --rate=48000 --channels=1 --stream-name=\"%s\" %s%s 2>/dev/null", nm, dev[0] ? "--device=" : "", dev);
    else if (!strcmp(m, "alsa"))     snprintf(out, n, "aplay -q -f S16_LE -r 48000 -c 1 %s%s - 2>/dev/null", dev[0] ? "-D " : "", dev);
    else if (!strcmp(m, "pipewire")) snprintf(out, n, "pw-cat -p --format s16 --rate 48000 --channels 1 %s%s - 2>/dev/null", dev[0] ? "--target " : "", dev);
    else if (!strcmp(m, "ffplay"))   snprintf(out, n, "ffplay -loglevel quiet -f s16le -ar 48000 -ac 1 -nodisp -autoexit - 2>/dev/null");
}

static void save_audio(tri_core *c) {
    if (!c->astore[0]) return;
    FILE *f = fopen(c->astore, "w");
    if (!f) { save_failed(c, c->astore); return; }
    fprintf(f, "%s\t%s\n", c->audio_method, c->audio_device);
    fclose(f);
}
static void load_audio(tri_core *c) {
    if (!c->astore[0]) return;
    FILE *f = fopen(c->astore, "r");
    if (!f) return;
    char line[300];
    if (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *m = strtok(line, "\t"), *d = strtok(NULL, "");
        if (m) snprintf(c->audio_method, sizeof c->audio_method, "%s", m);
        if (d) snprintf(c->audio_device, sizeof c->audio_device, "%s", d);
    }
    fclose(f);
}

void tri_audio_set(tri_core *c, const char *method, const char *device) {
    snprintf(c->audio_method, sizeof c->audio_method, "%s", method ? method : "auto");
    snprintf(c->audio_device, sizeof c->audio_device, "%s", device ? device : "");
    save_audio(c);
}
void tri_audio_get(tri_core *c, const char **method, const char **device) {
    *method = c->audio_method[0] ? c->audio_method : "auto";
    *device = c->audio_device;
}

void tri_audio_command(tri_core *c, char *out, size_t n) {
    char m[24]; snprintf(m, sizeof m, "%s", c->audio_method[0] ? c->audio_method : "auto");
    out[0] = '\0';
#ifdef TRI_PULSE
    if (!strcmp(m, "auto") || !strcmp(m, "pulse")) { snprintf(out, n, "PulseAudio (native libpulse)"); return; }
#else
    if (!strcmp(m, "auto")) {
        if      (have_cmd("pacat"))  snprintf(m, sizeof m, "pulse");
        else if (have_cmd("aplay"))  snprintf(m, sizeof m, "alsa");
        else if (have_cmd("pw-cat")) snprintf(m, sizeof m, "pipewire");
        else if (have_cmd("ffplay")) snprintf(m, sizeof m, "ffplay");
        else return;
    }
#endif
    build_cmd(m, c->audio_device, "voice", out, n);
}

static void audio_write_raw(tri_audio_sink *s, const int16_t *pcm, int samples) {
#ifdef TRI_PULSE
    if (s->pa) { int err = 0; pa_simple_write(s->pa, pcm, (size_t)samples * 2, &err); return; }
#endif
    if (s->pipe) { fwrite(pcm, 2, samples, s->pipe); fflush(s->pipe); }
}
static void *audio_thread(void *ud) {
    tri_audio_sink *s = ud;
    int16_t chunk[AUDIO_WR_CHUNK];
    for (;;) {
        pthread_mutex_lock(&s->lock);
        while (s->count == 0 && !s->stop) pthread_cond_wait(&s->cond, &s->lock);
        if (s->count == 0 && s->stop) { pthread_mutex_unlock(&s->lock); break; }
        int n = (int)(s->count < AUDIO_WR_CHUNK ? s->count : AUDIO_WR_CHUNK);
        for (int i = 0; i < n; i++) { chunk[i] = s->ring[s->head]; s->head = (s->head + 1) % AUDIO_RING_CAP; }
        s->count -= n;
        pthread_mutex_unlock(&s->lock);
        audio_write_raw(s, chunk, n);
    }
    return NULL;
}

static tri_audio_sink *audio_start(tri_audio_sink *s) {
    if (pthread_mutex_init(&s->lock, NULL) != 0) return s;
    if (pthread_cond_init(&s->cond, NULL) != 0) { pthread_mutex_destroy(&s->lock); return s; }
    if (pthread_create(&s->thread, NULL, audio_thread, s) != 0) {
        pthread_cond_destroy(&s->cond); pthread_mutex_destroy(&s->lock); return s;
    }
    s->threaded = 1;
    return s;
}
tri_audio_sink *tri_audio_open(tri_core *c) { return tri_audio_open_named(c, "voice"); }

tri_audio_sink *tri_audio_open_named(tri_core *c, const char *name) {
    adopt_user_audio();
    const char *m = c->audio_method[0] ? c->audio_method : "auto";
    const char *dev = c->audio_device;
    if (!name || !name[0]) name = "voice";
    tri_audio_sink *s = calloc(1, sizeof *s);
    if (!s) { tri_set_error("out of memory"); return NULL; }
#ifdef TRI_PULSE
    if (!strcmp(m, "auto") || !strcmp(m, "pulse")) {
        pa_sample_spec ss; ss.format = PA_SAMPLE_S16NE; ss.rate = 48000; ss.channels = 1;
        int err = 0;
        s->pa = pa_simple_new(NULL, "Trichat", PA_STREAM_PLAYBACK, dev[0] ? dev : NULL, name, &ss, NULL, NULL, &err);
        if (s->pa) return audio_start(s);
        if (!strcmp(m, "pulse")) { tri_set_error("pulse: %s", pa_strerror(err)); free(s); return NULL; }

    }
#endif
    char method[24]; snprintf(method, sizeof method, "%s", m);
    if (!strcmp(method, "auto")) {
        if      (have_cmd("aplay"))  snprintf(method, sizeof method, "alsa");
        else if (have_cmd("pw-cat")) snprintf(method, sizeof method, "pipewire");
        else if (have_cmd("pacat"))  snprintf(method, sizeof method, "pulse");
        else if (have_cmd("ffplay")) snprintf(method, sizeof method, "ffplay");
        else { tri_set_error("no audio backend found (install libpulse, alsa-utils, pipewire or ffmpeg)"); free(s); return NULL; }
    }
    char cmd[512]; build_cmd(method, dev, name, cmd, sizeof cmd);
    if (!cmd[0]) { tri_set_error("unknown audio method '%s'", method); free(s); return NULL; }
    signal(SIGPIPE, SIG_IGN);
    s->pipe = popen(cmd, "w");
    if (!s->pipe) { tri_set_error("could not start audio player"); free(s); return NULL; }
    return audio_start(s);
}

void tri_audio_write(tri_audio_sink *s, const int16_t *pcm, int samples) {
    if (!s || samples <= 0) return;
    if (!s->threaded) { audio_write_raw(s, pcm, samples); return; }
    pthread_mutex_lock(&s->lock);
    if (s->count + (size_t)samples <= AUDIO_RING_CAP) {
        for (int i = 0; i < samples; i++) { s->ring[s->tail] = pcm[i]; s->tail = (s->tail + 1) % AUDIO_RING_CAP; }
        s->count += (size_t)samples;
        pthread_cond_signal(&s->cond);
    }
    pthread_mutex_unlock(&s->lock);
}
void tri_audio_close(tri_audio_sink *s) {
    if (!s) return;
    if (s->threaded) {
        pthread_mutex_lock(&s->lock); s->stop = 1; pthread_cond_signal(&s->cond); pthread_mutex_unlock(&s->lock);
        pthread_join(s->thread, NULL);
        pthread_cond_destroy(&s->cond); pthread_mutex_destroy(&s->lock);
    }
#ifdef TRI_PULSE
    if (s->pa) { int err = 0; pa_simple_drain(s->pa, &err); pa_simple_free(s->pa); }
#endif
    if (s->pipe) pclose(s->pipe);
    free(s);
}

struct tri_audio_source {
    FILE *pipe;
    int   fd;
    uint8_t rem; int have_rem;
};

static void build_rec_cmd(const char *m, const char *dev, char *out, size_t n) {
    out[0] = '\0';
    if (!strcmp(m, "pulse"))         snprintf(out, n, "parec --format=s16le --rate=48000 --channels=1 %s%s 2>/dev/null", dev[0] ? "--device=" : "", dev);
    else if (!strcmp(m, "alsa"))     snprintf(out, n, "arecord -q -f S16_LE -r 48000 -c 1 -t raw %s%s 2>/dev/null", dev[0] ? "-D " : "", dev);
    else if (!strcmp(m, "pipewire")) snprintf(out, n, "pw-record --format s16 --rate 48000 --channels 1 %s%s - 2>/dev/null", dev[0] ? "--target " : "", dev);
    else if (!strcmp(m, "ffmpeg"))   snprintf(out, n, "ffmpeg -loglevel quiet -f pulse -i %s -ar 48000 -ac 1 -f s16le - 2>/dev/null", dev[0] ? dev : "default");
}

tri_audio_source *tri_audio_capture_open(tri_core *c, const char *dev) {
    adopt_user_audio();
    const char *m = c->audio_method[0] ? c->audio_method : "auto";
    if (!dev) dev = "";
    char method[24]; snprintf(method, sizeof method, "%s", m);
    if (!strcmp(method, "auto") || !strcmp(method, "pulse")) {
        if      (have_cmd("parec"))     snprintf(method, sizeof method, "pulse");
        else if (have_cmd("pw-record")) snprintf(method, sizeof method, "pipewire");
        else if (have_cmd("arecord"))   snprintf(method, sizeof method, "alsa");
        else if (have_cmd("ffmpeg"))    snprintf(method, sizeof method, "ffmpeg");
        else { tri_set_error("no mic recorder found (install pulseaudio-utils, pipewire, alsa-utils or ffmpeg)"); return NULL; }
    }
    char cmd[512]; build_rec_cmd(method, dev, cmd, sizeof cmd);
    if (!cmd[0]) { tri_set_error("unknown capture method '%s'", method); return NULL; }
    tri_audio_source *s = calloc(1, sizeof *s);
    if (!s) { tri_set_error("out of memory"); return NULL; }
    s->pipe = popen(cmd, "r");
    if (!s->pipe) { tri_set_error("could not start mic recorder"); free(s); return NULL; }
    s->fd = fileno(s->pipe);
    int fl = fcntl(s->fd, F_GETFL, 0); if (fl >= 0) fcntl(s->fd, F_SETFL, fl | O_NONBLOCK);
    return s;
}
int tri_audio_source_fd(tri_audio_source *s) { return s ? s->fd : -1; }

int tri_audio_source_read(tri_audio_source *s, int16_t *pcm, int max_samples) {
    if (!s || max_samples <= 0) return 0;
    uint8_t *buf = (uint8_t *)pcm;
    int cap = max_samples * 2, off = 0;
    if (s->have_rem) { buf[0] = s->rem; off = 1; s->have_rem = 0; }
    ssize_t n = read(s->fd, buf + off, (size_t)(cap - off));
    if (n == 0) return -1;
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    int total = off + (int)n;
    if (total & 1) { s->rem = buf[total - 1]; s->have_rem = 1; }
    return total / 2;
}
void tri_audio_capture_close(tri_audio_source *s) {
    if (!s) return;
    if (s->pipe) pclose(s->pipe);
    free(s);
}

int tri_audio_test(tri_core *c) {
    tri_audio_sink *s = tri_audio_open(c);
    if (!s) return -1;
    int16_t buf[4800];
    for (int chunk = 0; chunk < 5; chunk++) {
        for (int i = 0; i < 4800; i++) { double t = (chunk * 4800 + i) / 48000.0; buf[i] = (int16_t)(8000 * sin(2 * M_PI * 440 * t)); }
        tri_audio_write(s, buf, 4800);
    }
    tri_audio_close(s);
    return 0;
}

void tri_core_set_store(tri_core *c, const char *path) {
    snprintf(c->store, sizeof c->store, "%s", path ? path : "");

    snprintf(c->fstore, sizeof c->fstore, "%s", c->store);
    char *ps = strrchr(c->fstore, '/'); char *pbase = ps ? ps + 1 : c->fstore;
    snprintf(pbase, sizeof c->fstore - (size_t)(pbase - c->fstore), "folders.tsv");
    snprintf(c->astore, sizeof c->astore, "%s", c->store);
    char *as = strrchr(c->astore, '/'); char *abase = as ? as + 1 : c->astore;
    snprintf(abase, sizeof c->astore - (size_t)(abase - c->astore), "audio.tsv");
    snprintf(c->cstore, sizeof c->cstore, "%s", c->store);
    char *cs = strrchr(c->cstore, '/'); char *cbase = cs ? cs + 1 : c->cstore;
    snprintf(cbase, sizeof c->cstore - (size_t)(cbase - c->cstore), "channels.tsv");
    snprintf(c->rstore, sizeof c->rstore, "%s", c->store);
    char *rs = strrchr(c->rstore, '/'); char *rbase = rs ? rs + 1 : c->rstore;
    snprintf(rbase, sizeof c->rstore - (size_t)(rbase - c->rstore), "rules.tsv");
    snprintf(c->sstore, sizeof c->sstore, "%s", c->store);
    char *ss = strrchr(c->sstore, '/'); char *sbase = ss ? ss + 1 : c->sstore;
    snprintf(sbase, sizeof c->sstore - (size_t)(sbase - c->sstore), "saved.tsv");
}

int tri_persistence_selftest(void) {
    int rc = -1;
    tri_core *c = calloc(1, sizeof *c), *d = calloc(1, sizeof *d);
    if (!c || !d) { free(c); free(d); return -1; }
    char cpath[64], spath[64];
    snprintf(cpath, sizeof cpath, "/tmp/tri-ptest-%d-ch.tsv", (int)getpid());
    snprintf(spath, sizeof spath, "/tmp/tri-ptest-%d-sv.tsv", (int)getpid());

    snprintf(c->cstore, sizeof c->cstore, "%s", cpath);
    c->log_global = 1;
    int i = chan_get_or_add(c, "irc:alice", "#chan");
    snprintf(c->chans[i].nick, 64, "AliceNick"); c->chans[i].logmode = 1; c->chans[i].notify = TRI_NOTIFY_MENTIONS; c->chans[i].member = 1;
    int j = chan_get_or_add(c, "irc:alice", "");
    c->chans[j].logmode = 0; c->chans[j].notify = TRI_NOTIFY_MUTE;
    (void)chan_get_or_add(c, "xmpp:bob", "room@x");
    save_channels(c);

    snprintf(d->cstore, sizeof d->cstore, "%s", cpath);
    load_channels(d);
    if (d->nchans != 3 || d->log_global != 1) { fprintf(stderr, "persist: channel count/global mismatch\n"); goto done; }
    int a = chan_find(d, "irc:alice", "#chan");
    if (a < 0 || strcmp(d->chans[a].nick, "AliceNick") || d->chans[a].logmode != 1 || d->chans[a].notify != TRI_NOTIFY_MENTIONS || d->chans[a].member != 1)
        { fprintf(stderr, "persist: channel row (nick/log/notify/member) not restored\n"); goto done; }
    int b = chan_find(d, "irc:alice", "");
    if (b < 0 || d->chans[b].nick[0] || d->chans[b].notify != TRI_NOTIFY_MUTE)
        { fprintf(stderr, "persist: account-wide row not restored\n"); goto done; }
    int e = chan_find(d, "xmpp:bob", "room@x");
    if (e < 0 || d->chans[e].nick[0] || d->chans[e].notify != 0)
        { fprintf(stderr, "persist: default channel row not restored\n"); goto done; }

    FILE *lf = fopen(cpath, "w");
    if (!lf) { fprintf(stderr, "persist: cannot write legacy file\n"); goto done; }
    fputs("G\t1\n", lf);
    fputs("C\tirc:carol\t#old\t1\tCarolNick\n", lf);
    fputs("C\tirc:carol\t-\t0\t\n", lf);
    fclose(lf);
    memset(d, 0, sizeof *d); snprintf(d->cstore, sizeof d->cstore, "%s", cpath);
    load_channels(d);
    int co = chan_find(d, "irc:carol", "#old");
    if (co < 0 || strcmp(d->chans[co].nick, "CarolNick") || d->chans[co].logmode != 1 || d->chans[co].notify != 0)
        { fprintf(stderr, "persist: legacy row lost its nick or misread notify\n"); goto done; }
    int cw = chan_find(d, "irc:carol", "");
    if (cw < 0 || d->chans[cw].nick[0] || d->chans[cw].notify != 0)
        { fprintf(stderr, "persist: legacy account-wide row not restored\n"); goto done; }

    snprintf(c->sstore, sizeof c->sstore, "%s", spath);
    tri_saved_add(c, "irc:alice", "#chan", "bob", "hello there world", 42);
    tri_saved_add(c, "xmpp:bob", "", "", "a direct message", 43);
    memset(d, 0, sizeof *d); snprintf(d->sstore, sizeof d->sstore, "%s", spath);
    load_saved(d);
    if (d->nsaved != 2) { fprintf(stderr, "persist: saved count mismatch\n"); goto done; }
    if (strcmp(d->saved[0].text, "hello there world") || strcmp(d->saved[0].nick, "bob") || strcmp(d->saved[0].target, "#chan") || d->saved[0].ts != 42)
        { fprintf(stderr, "persist: saved row 0 not restored\n"); goto done; }
    if (strcmp(d->saved[1].text, "a direct message") || d->saved[1].nick[0] || d->saved[1].target[0] || d->saved[1].ts != 43)
        { fprintf(stderr, "persist: saved row 1 (empty nick/target) not restored\n"); goto done; }

    rc = 0;
done:
    unlink(cpath); unlink(spath);
    free(c); free(d);
    return rc;
}

static void save_folders(tri_core *c) {
    if (!c->fstore[0]) return;
    FILE *f = fopen(c->fstore, "w");
    if (!f) { save_failed(c, c->fstore); return; }
    for (tri_folder_t *fd = c->folders; fd; fd = fd->next)
        fprintf(f, "F\t%d\t%s\t%d\n", fd->id, fd->name, fd->parent ? fd->parent->id : 0);
    for (account_t *a = c->accounts; a; a = a->next)
        if (a->folder) fprintf(f, "A\t%d\t%s\n", a->folder->id, a->key);
    for (int i = 0; i < c->nrefs; i++)
        fprintf(f, "R\t%d\t%s\t%s\n", c->refs[i].folder_id, c->refs[i].acctkey, c->refs[i].target);
    fclose(f);
    chmod(c->fstore, 0600);
}

static void load_folder_defs(tri_core *c) {
    if (!c->fstore[0]) return;
    FILE *f = fopen(c->fstore, "r");
    if (!f) return;
    char line[400];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] != 'F') continue;
        strtok(line, "\t");
        char *ids = strtok(NULL, "\t"), *name = strtok(NULL, "\t"), *pids = strtok(NULL, "");
        if (!ids || !name) continue;
        tri_folder_t *fd = calloc(1, sizeof *fd);
        if (!fd) break;
        fd->id = atoi(ids);
        snprintf(fd->name, sizeof fd->name, "%s", name);
        fd->parent = NULL;
        fd->order = c->order_seq++;
        fd->core = c;
        fd->next = c->folders;
        c->folders = fd;
        if (fd->id >= c->next_folder_id) c->next_folder_id = fd->id + 1;
        fd->parent = (tri_folder_t *)(intptr_t)(pids ? atoi(pids) : 0);
    }

    for (tri_folder_t *fd = c->folders; fd; fd = fd->next)
        fd->parent = folder_by_id(c, (int)(intptr_t)fd->parent);
    fclose(f);
}

static void load_folder_members(tri_core *c) {
    if (!c->fstore[0]) return;
    FILE *f = fopen(c->fstore, "r");
    if (!f) return;
    char line[400];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == 'A') {
            strtok(line, "\t");
            char *fid = strtok(NULL, "\t"), *akey = strtok(NULL, "");
            if (!fid || !akey) continue;
            account_t *a = tri_account_find_by_key(c, akey);
            tri_folder_t *fd = folder_by_id(c, atoi(fid));
            if (a && fd) a->folder = fd;
        } else if (line[0] == 'R' && c->nrefs < MAX_FOLDER_REFS) {
            strtok(line, "\t");
            char *fid = strtok(NULL, "\t"), *akey = strtok(NULL, "\t"), *tgt = strtok(NULL, "");
            if (!fid || !akey) continue;
            chanref_t *r = &c->refs[c->nrefs++];
            r->folder_id = atoi(fid);
            snprintf(r->acctkey, sizeof r->acctkey, "%s", akey);
            snprintf(r->target, sizeof r->target, "%s", tgt ? tgt : "");
            r->order = c->order_seq++;
        }
    }
    fclose(f);
}

static void save_failed(tri_core *c, const char *path) {
    if (c->save_warned) return;
    c->save_warned = 1;
    tri_set_error("cannot save to %s: %s (settings will not persist)", path, strerror(errno));
    fprintf(stderr, "trichat: %s\n", tri_last_error());
    tri_event_t ev = { TRI_EV_ERROR, NULL, NULL, tri_last_error(), NULL, 0 };
    tri_emit(c, &ev);
}

static void save_accounts(tri_core *c) {
    if (!c->store[0]) return;
    FILE *f = fopen(c->store, "w");
    if (!f) { save_failed(c, c->store); return; }
    for (account_t *a = c->accounts; a; a = a->next)
        if (strcmp(a->backend->name, "echo"))
            fprintf(f, "%s\t%s\t%s\t%d\t%d\n", a->backend->name, a->name, a->config, a->autoconnect, a->insecure);
    fclose(f);
    chmod(c->store, 0600);
}

int tri_accounts_load(tri_core *c) {
    load_folder_defs(c);
    load_audio(c);
    load_channels(c);
    load_rules(c);
    load_saved(c);
    if (!c->store[0]) { load_folder_members(c); return 0; }
    FILE *f = fopen(c->store, "r");
    if (!f) { load_folder_members(c); return 0; }
    char line[800]; int n = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) continue;

        char *backend = strtok(line, "\t"), *name = strtok(NULL, "\t"), *config = strtok(NULL, "");
        int autoc = 1, insec = 0;
        if (config) {
            int flags[2], nf = 0;
            while (nf < 2) {
                char *tab = strrchr(config, '\t');
                if (tab && (tab[1] == '0' || tab[1] == '1') && tab[2] == '\0') { flags[nf++] = tab[1] - '0'; *tab = '\0'; }
                else break;
            }
            if (nf == 2)      { insec = flags[0]; autoc = flags[1]; }
            else if (nf == 1) { autoc = flags[0]; }
        }
        if (backend && name) {
            account_t *a = account_new(c, backend, name, config);
            if (a) { a->autoconnect = autoc; a->insecure |= insec;
                     if (autoc) { if (tri_account_connect(a) == 0) n++; } }
        }
    }
    fclose(f);
    load_folder_members(c);
    return n;
}

static void tls_pin_path(tri_core *c, char *out, size_t n) {
    char base[520];
    if (c->store[0]) { snprintf(base, sizeof base, "%s", c->store); char *sl = strrchr(base, '/'); if (sl) *sl = '\0'; else base[0] = '\0'; }
    else base[0] = '\0';
    snprintf(out, n, "%s/tls_pins.tsv", base[0] ? base : ".");
}
int tri_tls_pin_check(tri_core *c, const char *host, const char *fp) {
    if (!c || !host || !host[0] || !fp || !fp[0]) return TRI_PIN_NEW;
    char path[560]; tls_pin_path(c, path, sizeof path);
    FILE *f = fopen(path, "r"); if (!f) return TRI_PIN_NEW;
    char line[300]; int res = TRI_PIN_NEW;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *h = strtok(line, "\t"), *pin = strtok(NULL, "\t");
        if (h && pin && !strcasecmp(h, host)) { res = strcasecmp(pin, fp) == 0 ? TRI_PIN_MATCH : TRI_PIN_MISMATCH; break; }
    }
    fclose(f);
    return res;
}
void tri_tls_pin_store(tri_core *c, const char *host, const char *fp) {
    if (!c || !c->store[0] || !host || !host[0] || !fp || !fp[0]) return;
    char path[560]; tls_pin_path(c, path, sizeof path);
    char keep[8192]; size_t kn = 0; keep[0] = '\0';
    FILE *f = fopen(path, "r");
    if (f) {
        char line[300];
        while (fgets(line, sizeof line, f)) {
            char copy[300]; snprintf(copy, sizeof copy, "%s", line); copy[strcspn(copy, "\r\n")] = '\0';
            char *h = strtok(copy, "\t");
            if (h && !strcasecmp(h, host)) continue;
            size_t L = strlen(line);
            if (kn + L < sizeof keep) { memcpy(keep + kn, line, L); kn += L; keep[kn] = '\0'; }
        }
        fclose(f);
    }
    FILE *o = fopen(path, "w"); if (!o) return;
    if (kn) fwrite(keep, 1, kn, o);
    fprintf(o, "%s\t%s\n", host, fp);
    fclose(o);
    chmod(path, 0600);
}

const char *tri_default_store_path(void) {
    static char path[512];
    const char *home = getenv("HOME");
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0]) snprintf(path, sizeof path, "%s/trichat", xdg);
    else if (home && home[0]) snprintf(path, sizeof path, "%s/.config/trichat", home);
    else return "trichat-accounts.tsv";
    mkdir_p(path);
    snprintf(path + strlen(path), sizeof path - strlen(path), "/accounts.tsv");
    return path;
}

int   tri_account_fd(const account_t *a)            { return a->fd; }
void  tri_account_set_fd(account_t *a, int fd)      { a->fd = fd; }
void *tri_account_priv(const account_t *a)          { return a->priv; }
void  tri_account_set_priv(account_t *a, void *p)   { a->priv = p; }
const char *tri_account_name(const account_t *a)    { return a->name; }
const char *tri_account_key(const account_t *a)     { return a->key; }
const char *tri_account_config(const account_t *a)  { return a->config; }
const char *tri_account_backend(const account_t *a) { return a->backend->name; }
tri_core   *tri_account_core(const account_t *a)    { return a->core; }
void tri_account_set_write_interest(account_t *a, int on) { a->want_write = on; }
