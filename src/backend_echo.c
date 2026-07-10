#include "trichat.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

typedef struct { int peer; } echo_priv;

static int echo_connect(account_t *a) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return tri_set_error("echo: socketpair failed for account '%s': %s",
                             tri_account_name(a), strerror(errno));
    static echo_priv priv_pool[64]; static int n = 0;
    echo_priv *p = &priv_pool[n++];
    p->peer = sv[1];
    tri_account_set_priv(a, p);
    tri_account_set_fd(a, sv[0]);

    tri_event_t ev = { TRI_EV_STATUS, tri_account_key(a), NULL, "connected (echo)", NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
    return 0;
}

static void echo_disconnect(account_t *a) {
    echo_priv *p = tri_account_priv(a);
    int fd = tri_account_fd(a);
    if (fd >= 0) close(fd);
    if (p && p->peer >= 0) { close(p->peer); p->peer = -1; }
    tri_event_t ev = { TRI_EV_STATUS, tri_account_key(a), NULL, "disconnected", NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static int echo_send(account_t *a, const char *target, const char *body) {
    echo_priv *p = tri_account_priv(a);
    char line[1024];
    int len = snprintf(line, sizeof line, "%s\t%s", target ? target : "", body);
    if (write(p->peer, line, len) != len)
        return tri_set_error("echo: write failed for account '%s': %s",
                             tri_account_name(a), strerror(errno));
    return 0;
}

static void echo_join(account_t *a, const char *target) {
    char msg[256]; snprintf(msg, sizeof msg, "joined %s", target);
    tri_event_t ev = { TRI_EV_STATUS, tri_account_key(a), target, msg, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static void echo_leave(account_t *a, const char *target) {
    char msg[256]; snprintf(msg, sizeof msg, "left %s", target);
    tri_event_t ev = { TRI_EV_STATUS, tri_account_key(a), target, msg, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

static void echo_on_readable(account_t *a, int fd) {
    char buf[1024];
    ssize_t r = read(fd, buf, sizeof buf - 1);
    if (r <= 0) return;
    buf[r] = '\0';
    char *tab = strchr(buf, '\t');
    const char *target = NULL, *body = buf;
    if (tab) { *tab = '\0'; target = buf; body = tab + 1; }
    tri_event_t ev = { TRI_EV_MESSAGE, tri_account_key(a), target, body, NULL, 0 };
    tri_emit(tri_account_core(a), &ev);
}

const protocol_backend_t backend_echo = {
    .name = "echo",
    .connect = echo_connect,
    .disconnect = echo_disconnect,
    .send_message = echo_send,
    .join = echo_join,
    .leave = echo_leave,
    .on_socket_readable = echo_on_readable,
    .tick = NULL,
};
