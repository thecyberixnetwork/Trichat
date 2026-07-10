#include "trichat.h"
#include "resolve.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/socket.h>

struct tri_resolve {
    tri_core      *c;
    int            fd;
    pid_t          pid;
    tri_resolve_cb cb;
    void          *ud;
    unsigned char  buf[320];
    int            len;
};

static void resolve_finish(tri_resolve *r, int ok, const struct sockaddr *sa,
                           socklen_t salen, int socktype, int proto, const char *err) {
    tri_core_remove_fd(r->c, r->fd);
    close(r->fd);
    if (r->pid > 0) waitpid(r->pid, NULL, 0);
    tri_resolve_cb cb = r->cb; void *ud = r->ud;
    free(r);
    cb(ud, ok, sa, salen, socktype, proto, err);
}

static void resolve_ready(void *ud, int fd) {
    tri_resolve *r = ud;
    for (;;) {
        if (r->len >= (int)sizeof r->buf) break;
        ssize_t n = read(fd, r->buf + r->len, sizeof r->buf - (size_t)r->len);
        if (n > 0)      { r->len += (int)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        break;
    }

    if (r->len < 1 || r->buf[0] == 0) {
        char m[300]; int mlen = r->len > 1 ? r->len - 1 : 0;
        if (mlen > (int)sizeof m - 1) mlen = (int)sizeof m - 1;
        if (mlen > 0) memcpy(m, r->buf + 1, (size_t)mlen);
        m[mlen] = '\0';
        resolve_finish(r, 0, NULL, 0, 0, 0, mlen ? m : "name resolution failed");
        return;
    }

    int socktype, proto, salen, off = 1;
    const int hdr = 1 + 3 * (int)sizeof(int);
    if (r->len < hdr) { resolve_finish(r, 0, NULL, 0, 0, 0, "resolver: short reply"); return; }
    memcpy(&socktype, r->buf + off, sizeof(int)); off += (int)sizeof(int);
    memcpy(&proto,    r->buf + off, sizeof(int)); off += (int)sizeof(int);
    memcpy(&salen,    r->buf + off, sizeof(int)); off += (int)sizeof(int);
    if (salen <= 0 || salen > (int)sizeof(struct sockaddr_storage) || off + salen > r->len) {
        resolve_finish(r, 0, NULL, 0, 0, 0, "resolver: malformed address"); return;
    }
    struct sockaddr_storage ss;
    memcpy(&ss, r->buf + off, (size_t)salen);
    resolve_finish(r, 1, (struct sockaddr *)&ss, (socklen_t)salen, socktype, proto, NULL);
}

tri_resolve *tri_resolve_start(tri_core *c, const char *host, const char *port,
                               int socktype, tri_resolve_cb cb, void *ud) {
    int pfd[2];
    if (pipe(pfd) != 0) { tri_set_error("resolve: pipe() failed: %s", strerror(errno)); return NULL; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]); close(pfd[1]);
        tri_set_error("resolve: fork() failed: %s", strerror(errno));
        return NULL;
    }
    if (pid == 0) {
        close(pfd[0]);
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_socktype = socktype;
        int e = getaddrinfo(host, port, &hints, &res);
        if (e != 0 || !res) {
            unsigned char st = 0;
            const char *msg = gai_strerror(e);
            (void)!write(pfd[1], &st, 1);
            (void)!write(pfd[1], msg, strlen(msg));
            _exit(0);
        }
        unsigned char st = 1;
        int st2 = res->ai_socktype, proto = res->ai_protocol, salen = (int)res->ai_addrlen;
        (void)!write(pfd[1], &st, 1);
        (void)!write(pfd[1], &st2,   sizeof(int));
        (void)!write(pfd[1], &proto, sizeof(int));
        (void)!write(pfd[1], &salen, sizeof(int));
        (void)!write(pfd[1], res->ai_addr, (size_t)salen);
        freeaddrinfo(res);
        _exit(0);
    }

    close(pfd[1]);
    fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL, 0) | O_NONBLOCK);

    tri_resolve *r = calloc(1, sizeof *r);
    if (!r) {
        close(pfd[0]); kill(pid, SIGKILL); waitpid(pid, NULL, 0);
        tri_set_error("resolve: out of memory");
        return NULL;
    }
    r->c = c; r->fd = pfd[0]; r->pid = pid; r->cb = cb; r->ud = ud;
    if (tri_core_add_fd(c, pfd[0], resolve_ready, r) != 0) {
        close(pfd[0]); kill(pid, SIGKILL); waitpid(pid, NULL, 0); free(r);
        return NULL;
    }
    return r;
}

void tri_resolve_cancel(tri_resolve *r) {
    if (!r) return;
    tri_core_remove_fd(r->c, r->fd);
    close(r->fd);
    if (r->pid > 0) { kill(r->pid, SIGKILL); waitpid(r->pid, NULL, 0); }
    free(r);
}
