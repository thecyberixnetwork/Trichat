#include "ice.h"
#include "stun.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define STUN_RETRY_MAX   7
#define STUN_RETRY_SECS  0.5
#define CHECK_RETRY_MAX  7
#define TURN_RETRY_MAX   7
#define TURN_LIFETIME    600
#define TURN_REFRESH_AT  240.0
#define ICE_MAX_PAIR     (2 * ICE_MAX_CAND)

enum { PAIR_WAIT = 0, PAIR_INPROG, PAIR_OK, PAIR_FAIL };
enum { TURN_OFF = 0, TURN_ALLOC_UNAUTH, TURN_ALLOC_AUTH, TURN_ALLOCATED, TURN_FAILED };
enum { PERM_NONE = 0, PERM_PENDING, PERM_OK };

typedef struct {
    char ip[46]; int port; unsigned priority; char type[12];
    struct sockaddr_in sa;
    int perm_state;
    uint8_t perm_txid[STUN_TXID_LEN];
    int perm_tries; double perm_last;
} ice_remote;

typedef struct {
    int remote_idx;
    int via_relay;
    int state;
    int use_candidate;
    int peer_nominated;
    uint8_t txid[STUN_TXID_LEN];
    int tries;
    double last_send;
} ice_pair;

struct ice_agent {
    int  fd;
    int  host_port;
    int  controlling;
    uint64_t tiebreak;
    char ufrag[16], pwd[40];
    ice_cand cand[ICE_MAX_CAND];
    int  ncand;

    int  gathering;
    uint8_t txid[STUN_TXID_LEN];
    struct sockaddr_in stun_srv;
    int    tries;
    double last_send;

    char rufrag[16], rpwd[40];
    ice_remote remote[ICE_MAX_CAND]; int nremote;
    ice_pair   pair[ICE_MAX_PAIR];   int npair;
    int  checking;
    int  state;
    int  sel_pair;

    int  turn_state;
    struct sockaddr_in turn_srv;
    char turn_user[192], turn_pass[192], turn_realm[192], turn_nonce[192];
    uint8_t turn_key[16];
    int  turn_have_key;
    uint8_t turn_txid[STUN_TXID_LEN];
    int  turn_tries; double turn_last;
    double turn_refresh_at;
    char relay_ip[46]; int relay_port;

    int  dbg_tx_check, dbg_tx_check_relay, dbg_rx_check, dbg_rx_check_relay, dbg_data_ind;
    int  dbg_app_tx, dbg_app_rx;
    int  dbg_relay_drop;
    void (*app_cb)(void *ud, const uint8_t *data, int len);
    void *app_ud;
};

static void process_stun(ice_agent *g, const uint8_t *buf, int n, const struct sockaddr_in *src, int via_relay);
static void turn_send_indication(ice_agent *g, const struct sockaddr_in *peer, const uint8_t *data, int len);
static void turn_kick_permission(ice_agent *g, ice_remote *r);
static void turn_add_relay_pairs(ice_agent *g);

static double now_mono(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) == 0) return t.tv_sec + t.tv_nsec / 1e9;
    return (double)time(NULL);
}
static void set_nonblock(int fd) { int fl = fcntl(fd, F_GETFL, 0); if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

static void gen_cred(char *ufrag, size_t uf, char *pwd, size_t pw) {
    static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char rb[32]; size_t i;
    WC_RNG rng; int have = (wc_InitRng(&rng) == 0);
    if (have && wc_RNG_GenerateBlock(&rng, rb, sizeof rb) != 0) have = 0;
    if (have) wc_FreeRng(&rng);
    for (i = 0; i + 1 < uf && i < 8;  i++) ufrag[i] = cs[(have ? rb[i]     : (unsigned char)rand()) % 62];
    ufrag[i] = '\0';
    for (i = 0; i + 1 < pw && i < 24; i++) pwd[i]   = cs[(have ? rb[8 + i] : (unsigned char)rand()) % 62];
    pwd[i] = '\0';
}

static unsigned ice_priority(int type_pref, int local_pref, int component) {
    return ((unsigned)type_pref << 24) | ((unsigned)local_pref << 8) | (unsigned)(256 - component);
}
static int type_pref_of(const char *type) {
    if (!strcmp(type, "host"))  return 126;
    if (!strcmp(type, "prflx")) return 110;
    if (!strcmp(type, "srflx")) return 100;
    return 0;
}

static int add_cand(ice_agent *g, const char *type, const char *ip, int port) {
    if (g->ncand >= ICE_MAX_CAND || !ip[0] || port <= 0) return 0;
    for (int i = 0; i < g->ncand; i++)
        if (!strcmp(g->cand[i].type, type) && !strcmp(g->cand[i].ip, ip) && g->cand[i].port == port) return 0;
    ice_cand *c = &g->cand[g->ncand++];
    snprintf(c->type, sizeof c->type, "%s", type);
    snprintf(c->ip, sizeof c->ip, "%s", ip);
    c->port = port; c->component = 1;
    snprintf(c->foundation, sizeof c->foundation, "%d", type_pref_of(type));
    c->priority = ice_priority(type_pref_of(type), 65535, 1);
    return 1;
}

static int local_ip_for(const char *dst_ip, int dst_port, char *out, size_t osz) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in d; memset(&d, 0, sizeof d);
    d.sin_family = AF_INET; d.sin_port = htons((uint16_t)dst_port);
    int rc = -1;
    if (inet_pton(AF_INET, dst_ip, &d.sin_addr) == 1 && connect(s, (struct sockaddr *)&d, sizeof d) == 0) {
        struct sockaddr_in l; socklen_t ll = sizeof l;
        if (getsockname(s, (struct sockaddr *)&l, &ll) == 0) { inet_ntop(AF_INET, &l.sin_addr, out, (socklen_t)osz); rc = 0; }
    }
    close(s);
    return rc;
}

ice_agent *ice_new(int controlling) {
    ice_agent *g = calloc(1, sizeof *g);
    if (!g) return NULL;
    g->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g->fd < 0) { free(g); return NULL; }
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY); sa.sin_port = 0;
    if (bind(g->fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(g->fd); free(g); return NULL; }
    socklen_t sl = sizeof sa;
    if (getsockname(g->fd, (struct sockaddr *)&sa, &sl) == 0) g->host_port = ntohs(sa.sin_port);
    set_nonblock(g->fd);
    g->controlling = controlling;
    g->sel_pair = -1;
    g->tiebreak = ((uint64_t)rand() << 40) ^ ((uint64_t)rand() << 20) ^ (uint64_t)rand();
    gen_cred(g->ufrag, sizeof g->ufrag, g->pwd, sizeof g->pwd);
    return g;
}
void ice_free(ice_agent *g) { if (!g) return; if (g->fd >= 0) close(g->fd); free(g); }
int  ice_fd(const ice_agent *g) { return g ? g->fd : -1; }
const char *ice_ufrag(const ice_agent *g) { return g ? g->ufrag : ""; }
const char *ice_pwd(const ice_agent *g) { return g ? g->pwd : ""; }
int  ice_gathering(const ice_agent *g) { return g && g->gathering; }
int  ice_candidate_count(const ice_agent *g) { return g ? g->ncand : 0; }
int  ice_candidate_get(const ice_agent *g, int i, ice_cand *out) {
    if (!g || i < 0 || i >= g->ncand) return 0;
    *out = g->cand[i]; return 1;
}

static void send_probe(ice_agent *g) {
    uint8_t buf[64]; stun_msg m;
    stun_begin(&m, buf, sizeof buf, STUN_BINDING_REQUEST, g->txid);
    stun_add_fingerprint(&m);
    int n = stun_finish(&m);
    if (n > 0) sendto(g->fd, buf, (size_t)n, 0, (struct sockaddr *)&g->stun_srv, sizeof g->stun_srv);
    g->last_send = now_mono();
}

void ice_set_turn(ice_agent *g, const char *turn_ip, int turn_port,
                  const char *user, const char *pass, const char *realm) {
    if (!g || !turn_ip || !turn_ip[0] || turn_port <= 0) return;
    memset(&g->turn_srv, 0, sizeof g->turn_srv);
    g->turn_srv.sin_family = AF_INET; g->turn_srv.sin_port = htons((uint16_t)turn_port);
    if (inet_pton(AF_INET, turn_ip, &g->turn_srv.sin_addr) != 1) return;
    snprintf(g->turn_user,  sizeof g->turn_user,  "%s", user  ? user  : "");
    snprintf(g->turn_pass,  sizeof g->turn_pass,  "%s", pass  ? pass  : "");
    snprintf(g->turn_realm, sizeof g->turn_realm, "%s", realm ? realm : "");
    g->turn_state = TURN_ALLOC_UNAUTH;
}

static void turn_add_auth(ice_agent *g, stun_msg *m) {
    stun_add_bytes(m, STUN_ATTR_USERNAME, g->turn_user, (uint16_t)strlen(g->turn_user));
    stun_add_bytes(m, STUN_ATTR_REALM,    g->turn_realm, (uint16_t)strlen(g->turn_realm));
    stun_add_bytes(m, STUN_ATTR_NONCE,    g->turn_nonce, (uint16_t)strlen(g->turn_nonce));
    stun_add_integrity(m, (const char *)g->turn_key, sizeof g->turn_key);
}

static void turn_send_allocate(ice_agent *g, int authed) {
    uint8_t buf[768]; stun_msg m;
    for (int i = 0; i < STUN_TXID_LEN; i++) g->turn_txid[i] = (uint8_t)rand();
    stun_begin(&m, buf, sizeof buf, TURN_ALLOCATE_REQUEST, g->turn_txid);
    stun_add_u32(&m, STUN_ATTR_REQUESTED_TRANSPORT, 17u << 24);
    stun_add_u32(&m, STUN_ATTR_LIFETIME, TURN_LIFETIME);
    if (authed) turn_add_auth(g, &m);
    int n = stun_finish(&m);
    if (n > 0) sendto(g->fd, buf, (size_t)n, 0, (struct sockaddr *)&g->turn_srv, sizeof g->turn_srv);
    g->turn_last = now_mono();
}

static void turn_send_refresh(ice_agent *g) {
    if (!g->turn_have_key) return;
    uint8_t buf[768]; stun_msg m;
    for (int i = 0; i < STUN_TXID_LEN; i++) g->turn_txid[i] = (uint8_t)rand();
    stun_begin(&m, buf, sizeof buf, TURN_REFRESH_REQUEST, g->turn_txid);
    stun_add_u32(&m, STUN_ATTR_LIFETIME, TURN_LIFETIME);
    turn_add_auth(g, &m);
    int n = stun_finish(&m);
    if (n > 0) sendto(g->fd, buf, (size_t)n, 0, (struct sockaddr *)&g->turn_srv, sizeof g->turn_srv);
}

int ice_gather(ice_agent *g, const char *stun_ip, int stun_port) {
    if (!g) return -1;
    char ip[46] = "";
    if (local_ip_for(stun_ip && stun_ip[0] ? stun_ip : "8.8.8.8", stun_port ? stun_port : 3478, ip, sizeof ip) == 0)
        add_cand(g, "host", ip, g->host_port);
    if (stun_ip && stun_ip[0] && stun_port) {
        memset(&g->stun_srv, 0, sizeof g->stun_srv);
        g->stun_srv.sin_family = AF_INET; g->stun_srv.sin_port = htons((uint16_t)stun_port);
        if (inet_pton(AF_INET, stun_ip, &g->stun_srv.sin_addr) != 1) return -1;
        for (int i = 0; i < STUN_TXID_LEN; i++) g->txid[i] = (uint8_t)rand();
        g->gathering = 1; g->tries = 1;
        send_probe(g);
    }
    if (g->turn_state == TURN_ALLOC_UNAUTH) { g->turn_tries = 1; turn_send_allocate(g, 0); }
    return 0;
}

static void ipv4_str(const uint8_t a[4], char *out, size_t osz) {
    snprintf(out, osz, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}
static void sa_ip(const struct sockaddr_in *sa, char *out, size_t osz) {
    inet_ntop(AF_INET, &sa->sin_addr, out, (socklen_t)osz);
}

void ice_set_remote_creds(ice_agent *g, const char *ufrag, const char *pwd) {
    if (!g) return;
    snprintf(g->rufrag, sizeof g->rufrag, "%s", ufrag ? ufrag : "");
    snprintf(g->rpwd, sizeof g->rpwd, "%s", pwd ? pwd : "");
}
static int remote_index_for(ice_agent *g, const char *ip, int port) {
    for (int i = 0; i < g->nremote; i++) if (!strcmp(g->remote[i].ip, ip) && g->remote[i].port == port) return i;
    return -1;
}
static ice_pair *pair_for_remote(ice_agent *g, int ri, int via_relay) {
    for (int i = 0; i < g->npair; i++)
        if (g->pair[i].remote_idx == ri && g->pair[i].via_relay == via_relay) return &g->pair[i];
    return NULL;
}
static ice_pair *pair_by_txid(ice_agent *g, const uint8_t *txid) {
    for (int i = 0; i < g->npair; i++)
        if (g->pair[i].state == PAIR_INPROG && !memcmp(g->pair[i].txid, txid, STUN_TXID_LEN)) return &g->pair[i];
    return NULL;
}
static void add_pair(ice_agent *g, int ri, int via_relay) {
    if (g->npair >= ICE_MAX_PAIR || pair_for_remote(g, ri, via_relay)) return;
    ice_pair *p = &g->pair[g->npair++];
    memset(p, 0, sizeof *p);
    p->remote_idx = ri; p->via_relay = via_relay; p->state = PAIR_WAIT;
}
int ice_add_remote(ice_agent *g, const char *ip, int port, unsigned priority, const char *type) {
    if (!g || g->nremote >= ICE_MAX_CAND || !ip || !ip[0] || port <= 0) return 0;
    if (remote_index_for(g, ip, port) >= 0) return 0;
    ice_remote *r = &g->remote[g->nremote];
    memset(r, 0, sizeof *r);
    snprintf(r->ip, sizeof r->ip, "%s", ip);
    r->port = port; r->priority = priority;
    snprintf(r->type, sizeof r->type, "%s", type ? type : "host");
    r->sa.sin_family = AF_INET; r->sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &r->sa.sin_addr) != 1) return 0;
    int ri = g->nremote++;
    add_pair(g, ri, 0);
    if (g->turn_state == TURN_ALLOCATED) {
        add_pair(g, ri, 1);
        turn_kick_permission(g, &g->remote[ri]);
    }
    return 1;
}

static void turn_add_relay_pairs(ice_agent *g) {
    for (int ri = 0; ri < g->nremote; ri++) {
        add_pair(g, ri, 1);
        turn_kick_permission(g, &g->remote[ri]);
    }
}
void ice_start_checks(ice_agent *g) { if (!g) return; if (g->state == ICE_NEW) g->state = ICE_CHECKING; g->checking = 1; }
void ice_set_app_cb(ice_agent *g, void (*cb)(void *ud, const uint8_t *data, int len), void *ud) { if (g) { g->app_cb = cb; g->app_ud = ud; } }
int  ice_send(ice_agent *g, const uint8_t *data, int len) {
    if (!g || g->sel_pair < 0 || len <= 0) return -1;
    ice_pair *p = &g->pair[g->sel_pair];
    struct sockaddr_in *sa = &g->remote[p->remote_idx].sa;
    g->dbg_app_tx++;
    if (p->via_relay) { turn_send_indication(g, sa, data, len); return len; }
    return (int)sendto(g->fd, data, (size_t)len, 0, (struct sockaddr *)sa, sizeof *sa);
}
int  ice_state(const ice_agent *g) { return g ? g->state : ICE_FAILED; }
int  ice_selected(const ice_agent *g, ice_cand *local, ice_cand *remote) {
    if (!g || g->sel_pair < 0) return 0;
    const ice_pair *p = &g->pair[g->sel_pair];
    const ice_remote *r = &g->remote[p->remote_idx];
    if (local) { const char *lt = p->via_relay ? "relay" : "host";
                 memset(local, 0, sizeof *local); snprintf(local->type, sizeof local->type, "%s", lt);
                 for (int i = 0; i < g->ncand; i++) if (!strcmp(g->cand[i].type, lt)) { *local = g->cand[i]; break; } }
    if (remote) { memset(remote, 0, sizeof *remote);
                  snprintf(remote->ip, sizeof remote->ip, "%s", r->ip);
                  remote->port = r->port; remote->priority = r->priority; remote->component = 1;
                  snprintf(remote->type, sizeof remote->type, "%s", r->type); }
    return 1;
}

static void sa_to_stun(const struct sockaddr_in *sa, stun_addr *a) {
    memset(a, 0, sizeof *a); a->family = 4;
    a->port = ntohs(sa->sin_port); memcpy(a->addr, &sa->sin_addr, 4);
}

static void turn_send_indication(ice_agent *g, const struct sockaddr_in *peer, const uint8_t *data, int len) {
    if (len <= 0) return;
    if (len > 1500) { g->dbg_relay_drop++; return; }
    uint8_t buf[1600]; stun_msg m; uint8_t txid[STUN_TXID_LEN];
    for (int i = 0; i < STUN_TXID_LEN; i++) txid[i] = (uint8_t)rand();
    stun_begin(&m, buf, sizeof buf, TURN_SEND_INDICATION, txid);
    stun_addr pa; sa_to_stun(peer, &pa);
    stun_add_xor_addr(&m, STUN_ATTR_XOR_PEER_ADDRESS, &pa);
    stun_add_bytes(&m, STUN_ATTR_DATA, data, (uint16_t)len);
    int n = stun_finish(&m);
    if (n > 0) sendto(g->fd, buf, (size_t)n, 0, (struct sockaddr *)&g->turn_srv, sizeof g->turn_srv);
}

static void turn_kick_permission(ice_agent *g, ice_remote *r) {
    if (g->turn_state != TURN_ALLOCATED || !g->turn_have_key) return;
    uint8_t buf[768]; stun_msg m;
    for (int i = 0; i < STUN_TXID_LEN; i++) r->perm_txid[i] = (uint8_t)rand();
    stun_begin(&m, buf, sizeof buf, TURN_CREATEPERM_REQUEST, r->perm_txid);
    stun_addr pa; sa_to_stun(&r->sa, &pa);
    stun_add_xor_addr(&m, STUN_ATTR_XOR_PEER_ADDRESS, &pa);
    turn_add_auth(g, &m);
    int n = stun_finish(&m);
    if (n > 0) sendto(g->fd, buf, (size_t)n, 0, (struct sockaddr *)&g->turn_srv, sizeof g->turn_srv);
    r->perm_state = PERM_PENDING; r->perm_last = now_mono();
}

static void send_check(ice_agent *g, ice_pair *p, int use_candidate) {
    uint8_t buf[160]; stun_msg m;
    stun_begin(&m, buf, sizeof buf, STUN_BINDING_REQUEST, p->txid);
    char user[40]; snprintf(user, sizeof user, "%s:%s", g->rufrag, g->ufrag);
    stun_add_bytes(&m, STUN_ATTR_USERNAME, user, (uint16_t)strlen(user));
    stun_add_u32(&m, STUN_ATTR_PRIORITY, ice_priority(type_pref_of("prflx"), 65535, 1));
    stun_add_u64(&m, g->controlling ? STUN_ATTR_ICE_CONTROLLING : STUN_ATTR_ICE_CONTROLLED, g->tiebreak);
    if (use_candidate) stun_add_flag(&m, STUN_ATTR_USE_CANDIDATE);
    stun_add_integrity(&m, g->rpwd, strlen(g->rpwd));
    stun_add_fingerprint(&m);
    int n = stun_finish(&m);
    struct sockaddr_in *sa = &g->remote[p->remote_idx].sa;
    if (n > 0) {
        if (p->via_relay) { turn_send_indication(g, sa, buf, n); g->dbg_tx_check_relay++; }
        else { sendto(g->fd, buf, (size_t)n, 0, (struct sockaddr *)sa, sizeof *sa); g->dbg_tx_check++; }
    }
    p->use_candidate = use_candidate;
    p->last_send = now_mono();
}

static void maybe_nominate_controlled(ice_agent *g, ice_pair *p) {
    if (!g->controlling && p->state == PAIR_OK && p->peer_nominated && g->sel_pair < 0) {
        g->sel_pair = (int)(p - g->pair); g->state = ICE_CONNECTED;
    }
}

static int sa_eq(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static void handle_turn(ice_agent *g, const uint8_t *buf, int n) {
    uint16_t type = stun_type(buf);

    uint16_t vl; const uint8_t *v;
    if ((v = stun_find(buf, (size_t)n, STUN_ATTR_REALM, &vl)) && vl < sizeof g->turn_realm && !g->turn_realm[0]) {
        memcpy(g->turn_realm, v, vl); g->turn_realm[vl] = '\0';
    }
    if ((v = stun_find(buf, (size_t)n, STUN_ATTR_NONCE, &vl)) && vl < sizeof g->turn_nonce) {
        memcpy(g->turn_nonce, v, vl); g->turn_nonce[vl] = '\0';
    }

    if (type == TURN_DATA_INDICATION) {
        stun_addr pa; uint16_t dl; const uint8_t *d = stun_find(buf, (size_t)n, STUN_ATTR_DATA, &dl);
        if (!d || stun_get_xor_addr(buf, (size_t)n, STUN_ATTR_XOR_PEER_ADDRESS, &pa) != 0 || pa.family != 4) return;
        struct sockaddr_in peer; memset(&peer, 0, sizeof peer);
        peer.sin_family = AF_INET; peer.sin_port = htons(pa.port); memcpy(&peer.sin_addr, pa.addr, 4);
        g->dbg_data_ind++;
        if (stun_check(d, dl)) process_stun(g, d, dl, &peer, 1);
        else if (g->app_cb) { g->dbg_app_rx++; g->app_cb(g->app_ud, d, dl); }
        return;
    }
    if (type == TURN_ALLOCATE_SUCCESS && !memcmp(stun_txid(buf), g->turn_txid, STUN_TXID_LEN)) {
        stun_addr ra;
        if (stun_get_xor_addr(buf, (size_t)n, STUN_ATTR_XOR_RELAYED_ADDRESS, &ra) == 0 && ra.family == 4) {
            ipv4_str(ra.addr, g->relay_ip, sizeof g->relay_ip); g->relay_port = ra.port;
            add_cand(g, "relay", g->relay_ip, g->relay_port);
        }
        stun_addr ma;
        if (stun_get_xor_addr(buf, (size_t)n, STUN_ATTR_XOR_MAPPED_ADDRESS, &ma) == 0 && ma.family == 4) {
            char ip[46]; ipv4_str(ma.addr, ip, sizeof ip); add_cand(g, "srflx", ip, ma.port);
        }
        g->turn_state = TURN_ALLOCATED;
        g->turn_refresh_at = now_mono() + TURN_REFRESH_AT;
        turn_add_relay_pairs(g);
        return;
    }
    if (type == TURN_ALLOCATE_ERROR && !memcmp(stun_txid(buf), g->turn_txid, STUN_TXID_LEN)) {
        int code = stun_error_code(buf, (size_t)n);
        if ((code == 401 || code == 438) && g->turn_state == TURN_ALLOC_UNAUTH && g->turn_user[0] && g->turn_realm[0]) {
            if (stun_longterm_key(g->turn_user, g->turn_realm, g->turn_pass, g->turn_key) == 0) g->turn_have_key = 1;
            if (g->turn_have_key) { g->turn_state = TURN_ALLOC_AUTH; g->turn_tries = 1; turn_send_allocate(g, 1); }
            else g->turn_state = TURN_FAILED;
        } else if (code == 438 && g->turn_state == TURN_ALLOC_AUTH) {
            g->turn_tries = 1; turn_send_allocate(g, 1);
        } else {
            g->turn_state = TURN_FAILED;
        }
        return;
    }
    if (type == TURN_CREATEPERM_SUCCESS) {
        for (int i = 0; i < g->nremote; i++)
            if (g->remote[i].perm_state == PERM_PENDING && !memcmp(g->remote[i].perm_txid, stun_txid(buf), STUN_TXID_LEN))
                g->remote[i].perm_state = PERM_OK;
        return;
    }

}

static void process_stun(ice_agent *g, const uint8_t *buf, int n, const struct sockaddr_in *src, int via_relay) {
    uint16_t type = stun_type(buf);

    if (type == STUN_BINDING_REQUEST) {
        if (stun_verify_integrity(buf, (size_t)n, g->pwd, strlen(g->pwd)) != 0) return;
        if (via_relay) g->dbg_rx_check_relay++; else g->dbg_rx_check++;
        int use_cand = stun_find(buf, (size_t)n, STUN_ATTR_USE_CANDIDATE, NULL) != NULL;
        char sip[46]; sa_ip(src, sip, sizeof sip); int sport = ntohs(src->sin_port);
        stun_addr ma; memset(&ma, 0, sizeof ma); ma.family = 4; ma.port = (uint16_t)sport; memcpy(ma.addr, &src->sin_addr, 4);
        uint8_t ob[160]; stun_msg om;
        stun_begin(&om, ob, sizeof ob, STUN_BINDING_SUCCESS, stun_txid(buf));
        stun_add_xor_addr(&om, STUN_ATTR_XOR_MAPPED_ADDRESS, &ma);
        stun_add_integrity(&om, g->pwd, strlen(g->pwd));
        stun_add_fingerprint(&om);
        int on = stun_finish(&om);
        if (on > 0) {
            if (via_relay) turn_send_indication(g, src, ob, on);
            else sendto(g->fd, ob, (size_t)on, 0, (struct sockaddr *)src, sizeof *src);
        }
        int ri = remote_index_for(g, sip, sport);
        if (ri < 0) { ice_add_remote(g, sip, sport, ice_priority(type_pref_of("prflx"), 65535, 1), "prflx");
                      ri = remote_index_for(g, sip, sport); }
        if (ri < 0) return;
        ice_pair *pp = pair_for_remote(g, ri, via_relay);
        if (!pp) { add_pair(g, ri, via_relay); pp = pair_for_remote(g, ri, via_relay); }
        if (pp && use_cand) { pp->peer_nominated = 1; maybe_nominate_controlled(g, pp); }
        return;
    }
    if (type == STUN_BINDING_SUCCESS) {
        if (!via_relay && g->gathering && !memcmp(stun_txid(buf), g->txid, STUN_TXID_LEN)) {
            stun_addr a;
            if (stun_get_xor_addr(buf, (size_t)n, STUN_ATTR_XOR_MAPPED_ADDRESS, &a) == 0 && a.family == 4) {
                char ip[46]; ipv4_str(a.addr, ip, sizeof ip);
                g->gathering = 0; add_cand(g, "srflx", ip, a.port);
            }
            return;
        }
        ice_pair *p = pair_by_txid(g, stun_txid(buf));
        if (p && stun_verify_integrity(buf, (size_t)n, g->rpwd, strlen(g->rpwd)) == 0) {
            int nominating = p->use_candidate;
            p->state = PAIR_OK;
            if (g->controlling) {
                if (nominating) { g->sel_pair = (int)(p - g->pair); g->state = ICE_CONNECTED; }
                else if (g->sel_pair < 0) {
                    p->state = PAIR_INPROG; p->tries = 1;
                    for (int i = 0; i < STUN_TXID_LEN; i++) p->txid[i] = (uint8_t)rand();
                    send_check(g, p, 1);
                }
            } else {
                maybe_nominate_controlled(g, p);
            }
        }
        return;
    }
}

int ice_on_readable(ice_agent *g) {
    if (!g) return 0;

    int prev = g->ncand;
    for (;;) {
        uint8_t buf[1500]; struct sockaddr_in src; socklen_t sl = sizeof src;
        ssize_t n = recvfrom(g->fd, buf, sizeof buf, 0, (struct sockaddr *)&src, &sl);
        if (n <= 0) break;
        if (g->turn_state != TURN_OFF && sa_eq(&src, &g->turn_srv) && stun_check(buf, (size_t)n)) {
            handle_turn(g, buf, (int)n);
        } else if (!stun_check(buf, (size_t)n)) {
            if (g->app_cb) { g->dbg_app_rx++; g->app_cb(g->app_ud, buf, (int)n); }
        } else {
            process_stun(g, buf, (int)n, &src, 0);
        }
    }
    return g->ncand != prev;
}

int ice_tick(ice_agent *g, double now) {
    if (!g) return 0;
    if (g->gathering && now - g->last_send >= STUN_RETRY_SECS) {
        if (g->tries >= STUN_RETRY_MAX) g->gathering = 0;
        else { g->tries++; send_probe(g); }
    }

    if ((g->turn_state == TURN_ALLOC_UNAUTH || g->turn_state == TURN_ALLOC_AUTH) && now - g->turn_last >= STUN_RETRY_SECS) {
        if (g->turn_tries >= TURN_RETRY_MAX) g->turn_state = TURN_FAILED;
        else { g->turn_tries++; turn_send_allocate(g, g->turn_state == TURN_ALLOC_AUTH); }
    }
    if (g->turn_state == TURN_ALLOCATED) {
        if (g->turn_refresh_at > 0 && now >= g->turn_refresh_at) {
            turn_send_refresh(g);
            for (int i = 0; i < g->nremote; i++) {
                g->remote[i].perm_tries = 0; turn_kick_permission(g, &g->remote[i]);
            }
            g->turn_refresh_at = now + TURN_REFRESH_AT;
        }
        for (int i = 0; i < g->nremote; i++) {
            ice_remote *r = &g->remote[i];
            if (r->perm_state == PERM_PENDING && now - r->perm_last >= STUN_RETRY_SECS) {
                if (r->perm_tries >= TURN_RETRY_MAX) r->perm_state = PERM_NONE;
                else { r->perm_tries++; turn_kick_permission(g, r); }
            }
        }
    }
    if (g->checking && g->state == ICE_CHECKING) {
        for (int i = 0; i < g->npair; i++) {
            ice_pair *p = &g->pair[i];
            if (p->state == PAIR_WAIT) {
                p->state = PAIR_INPROG; p->tries = 1;
                for (int j = 0; j < STUN_TXID_LEN; j++) p->txid[j] = (uint8_t)rand();
                send_check(g, p, 0);
            } else if (p->state == PAIR_INPROG && now - p->last_send >= STUN_RETRY_SECS) {
                if (p->tries >= CHECK_RETRY_MAX) p->state = PAIR_FAIL;
                else { p->tries++; send_check(g, p, p->use_candidate); }
            }
        }
    }
    return 0;
}

void ice_debug(const ice_agent *g, char *out, size_t n) {
    if (!g || !out || n == 0) { if (out && n) out[0] = '\0'; return; }
    static const char *TS[] = { "off", "alloc-unauth", "alloc-auth", "allocated", "FAILED" };
    static const char *PS[] = { "new", "checking", "connected", "FAILED" };
    static const char *PR[] = { "none", "pending", "ok" };
    static const char *PST[] = { "wait", "inprog", "OK", "fail" };
    size_t k = 0;
    k += snprintf(out + k, n - k, "ICE %s role=%s turn=%s",
                  g->state <= ICE_FAILED ? PS[g->state] : "?",
                  g->controlling ? "controlling" : "controlled",
                  (g->turn_state >= 0 && g->turn_state <= TURN_FAILED) ? TS[g->turn_state] : "?");
    if (g->relay_ip[0]) k += snprintf(out + k, n - k, " relay=%s:%d", g->relay_ip, g->relay_port);
    k += snprintf(out + k, n - k, " tx=%d/%dR rx=%d/%dR data-ind=%d media-tx=%d media-rx=%d",
                  g->dbg_tx_check, g->dbg_tx_check_relay, g->dbg_rx_check, g->dbg_rx_check_relay,
                  g->dbg_data_ind, g->dbg_app_tx, g->dbg_app_rx);
    if (g->dbg_relay_drop) k += snprintf(out + k, n - k, " relay-drop=%d", g->dbg_relay_drop);
    if (g->sel_pair >= 0) {
        const ice_pair *sp = &g->pair[g->sel_pair];
        k += snprintf(out + k, n - k, " sel=%s:%d%s", g->remote[sp->remote_idx].ip,
                      g->remote[sp->remote_idx].port, sp->via_relay ? "[relay]" : "[direct]");
    }
    for (int i = 0; i < g->nremote && k < n; i++) {
        const ice_remote *r = &g->remote[i];
        k += snprintf(out + k, n - k, " | %s:%d(%s) perm=%s", r->ip, r->port, r->type,
                      (r->perm_state >= 0 && r->perm_state <= PERM_OK) ? PR[r->perm_state] : "?");
    }
    for (int i = 0; i < g->npair && k < n; i++) {
        const ice_pair *p = &g->pair[i];
        const ice_remote *r = &g->remote[p->remote_idx];
        k += snprintf(out + k, n - k, " || %s:%d%s %s%s", r->ip, r->port, p->via_relay ? "[relay]" : "",
                      (p->state >= 0 && p->state <= PAIR_FAIL) ? PST[p->state] : "?",
                      p->peer_nominated ? "+nom" : "");
    }
}

static int wait_readable(int fd, int ms) {
    fd_set r; FD_ZERO(&r); FD_SET(fd, &r);
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    return select(fd + 1, &r, NULL, NULL, &tv) > 0;
}

int ice_selftest(void) {
    if (ice_priority(126, 65535, 1) <= ice_priority(100, 65535, 1)) return -1;

    ice_agent *g = ice_new(1);
    if (!g) return -2;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { ice_free(g); return -3; }
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) { close(s); ice_free(g); return -4; }
    socklen_t sl = sizeof sa; getsockname(s, (struct sockaddr *)&sa, &sl);
    int sport = ntohs(sa.sin_port);

    if (ice_gather(g, "127.0.0.1", sport) != 0) { close(s); ice_free(g); return -5; }

    if (!wait_readable(s, 1000)) { close(s); ice_free(g); return -6; }
    uint8_t rb[1500]; struct sockaddr_in src; socklen_t srl = sizeof src;
    ssize_t rn = recvfrom(s, rb, sizeof rb, 0, (struct sockaddr *)&src, &srl);
    if (rn <= 0 || !stun_check(rb, (size_t)rn) || stun_type(rb) != STUN_BINDING_REQUEST) { close(s); ice_free(g); return -7; }

    stun_addr ma; memset(&ma, 0, sizeof ma);
    ma.family = 4; ma.port = ntohs(src.sin_port); memcpy(ma.addr, &src.sin_addr, 4);
    uint8_t ob[128]; stun_msg m;
    stun_begin(&m, ob, sizeof ob, STUN_BINDING_SUCCESS, stun_txid(rb));
    stun_add_xor_addr(&m, STUN_ATTR_XOR_MAPPED_ADDRESS, &ma);
    stun_add_fingerprint(&m);
    int on = stun_finish(&m);
    if (on <= 0 || sendto(s, ob, (size_t)on, 0, (struct sockaddr *)&src, srl) != on) { close(s); ice_free(g); return -8; }

    int got = 0;
    if (wait_readable(ice_fd(g), 1000)) for (int t = 0; t < 5 && !got; t++) got = ice_on_readable(g);
    close(s);

    int have_host = 0, have_srflx = 0;
    for (int i = 0; i < ice_candidate_count(g); i++) {
        ice_cand c; ice_candidate_get(g, i, &c);
        if (!strcmp(c.type, "host"))  have_host = 1;
        if (!strcmp(c.type, "srflx")) { have_srflx = 1;
            if (strcmp(c.ip, "127.0.0.1") || c.port != g->host_port) { ice_free(g); return -9; } }
    }
    ice_free(g);
    if (!have_host)  return -10;
    if (!have_srflx) return -11;

    ice_agent *A = ice_new(1), *B = ice_new(0);
    if (!A || !B) { ice_free(A); ice_free(B); return -12; }
    ice_gather(A, "127.0.0.1", 0); ice_gather(B, "127.0.0.1", 0);
    if (ice_candidate_count(A) < 1 || ice_candidate_count(B) < 1) { ice_free(A); ice_free(B); return -13; }
    ice_set_remote_creds(A, ice_ufrag(B), ice_pwd(B));
    ice_set_remote_creds(B, ice_ufrag(A), ice_pwd(A));
    for (int i = 0; i < ice_candidate_count(B); i++) { ice_cand c; ice_candidate_get(B, i, &c); ice_add_remote(A, c.ip, c.port, c.priority, c.type); }
    for (int i = 0; i < ice_candidate_count(A); i++) { ice_cand c; ice_candidate_get(A, i, &c); ice_add_remote(B, c.ip, c.port, c.priority, c.type); }
    ice_start_checks(A); ice_start_checks(B);
    double t0 = now_mono();
    while (now_mono() - t0 < 3.0 && !(ice_state(A) == ICE_CONNECTED && ice_state(B) == ICE_CONNECTED)) {
        ice_tick(A, now_mono()); ice_tick(B, now_mono());
        fd_set r; FD_ZERO(&r); int fa = ice_fd(A), fb = ice_fd(B);
        FD_SET(fa, &r); FD_SET(fb, &r);
        struct timeval tv = { 0, 20000 };
        if (select((fa > fb ? fa : fb) + 1, &r, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(fa, &r)) ice_on_readable(A);
            if (FD_ISSET(fb, &r)) ice_on_readable(B);
        }
    }
    int okA = ice_state(A) == ICE_CONNECTED, okB = ice_state(B) == ICE_CONNECTED;
    ice_cand la, ra; int selA = ice_selected(A, &la, &ra);
    ice_free(A); ice_free(B);
    if (!okA || !okB) return -14;
    if (!selA || strcmp(ra.ip, "127.0.0.1")) return -15;

    int ts = socket(AF_INET, SOCK_DGRAM, 0);
    if (ts < 0) return -16;
    struct sockaddr_in tsa; memset(&tsa, 0, sizeof tsa);
    tsa.sin_family = AF_INET; tsa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); tsa.sin_port = 0;
    if (bind(ts, (struct sockaddr *)&tsa, sizeof tsa) < 0) { close(ts); return -17; }
    socklen_t tsl = sizeof tsa; getsockname(ts, (struct sockaddr *)&tsa, &tsl);
    int tport = ntohs(tsa.sin_port);

    ice_agent *T = ice_new(0);
    if (!T) { close(ts); return -18; }
    ice_set_turn(T, "127.0.0.1", tport, "user", "pass", "");
    ice_gather(T, NULL, 0);
    ice_add_remote(T, "127.0.0.1", 55555, 100, "srflx");

    double tt0 = now_mono();
    int perm_ok = 0;
    while (now_mono() - tt0 < 3.0 && !(T->turn_state == TURN_ALLOCATED && perm_ok)) {
        ice_tick(T, now_mono());
        fd_set r; FD_ZERO(&r); int ft = ice_fd(T);
        FD_SET(ft, &r); FD_SET(ts, &r); int mx = ft > ts ? ft : ts;
        struct timeval tv = { 0, 20000 };
        if (select(mx + 1, &r, NULL, NULL, &tv) <= 0) continue;
        if (FD_ISSET(ft, &r)) ice_on_readable(T);
        if (FD_ISSET(ts, &r)) {
            uint8_t rb[1500]; struct sockaddr_in from; socklen_t fl = sizeof from;
            ssize_t rn = recvfrom(ts, rb, sizeof rb, 0, (struct sockaddr *)&from, &fl);
            if (rn <= 0 || !stun_check(rb, (size_t)rn)) continue;
            uint16_t mt = stun_type(rb);
            uint8_t ob[300]; stun_msg om;
            if (mt == TURN_ALLOCATE_REQUEST) {
                if (!stun_find(rb, (size_t)rn, STUN_ATTR_MESSAGE_INTEGRITY, NULL)) {
                    stun_begin(&om, ob, sizeof ob, TURN_ALLOCATE_ERROR, stun_txid(rb));
                    uint8_t ec[4] = { 0, 0, 4, 1 };
                    stun_add_bytes(&om, STUN_ATTR_ERROR_CODE, ec, 4);
                    stun_add_bytes(&om, STUN_ATTR_REALM, "test", 4);
                    stun_add_bytes(&om, STUN_ATTR_NONCE, "nonce123", 8);
                } else {
                    stun_begin(&om, ob, sizeof ob, TURN_ALLOCATE_SUCCESS, stun_txid(rb));
                    stun_addr rel = { 4, { 127, 0, 0, 1 }, 41000 };
                    stun_add_xor_addr(&om, STUN_ATTR_XOR_RELAYED_ADDRESS, &rel);
                }
                int n2 = stun_finish(&om);
                sendto(ts, ob, (size_t)n2, 0, (struct sockaddr *)&from, fl);
            } else if (mt == TURN_CREATEPERM_REQUEST) {
                stun_begin(&om, ob, sizeof ob, TURN_CREATEPERM_SUCCESS, stun_txid(rb));
                int n2 = stun_finish(&om);
                sendto(ts, ob, (size_t)n2, 0, (struct sockaddr *)&from, fl);
            }
        }
        if (T->nremote > 0 && T->remote[0].perm_state == PERM_OK) perm_ok = 1;
    }
    int have_relay = 0;
    for (int i = 0; i < ice_candidate_count(T); i++) {
        ice_cand c; ice_candidate_get(T, i, &c);
        if (!strcmp(c.type, "relay")) { have_relay = (!strcmp(c.ip, "127.0.0.1") && c.port == 41000); }
    }
    int allocated = T->turn_state == TURN_ALLOCATED;
    close(ts); ice_free(T);
    if (!allocated)  return -19;
    if (!have_relay) return -20;
    if (!perm_ok)    return -21;
    return 0;
}
