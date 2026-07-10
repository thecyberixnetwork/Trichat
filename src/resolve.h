#ifndef TRICHAT_RESOLVE_H
#define TRICHAT_RESOLVE_H
#include <sys/socket.h>

typedef struct tri_core    tri_core;
typedef struct tri_resolve tri_resolve;

typedef void (*tri_resolve_cb)(void *ud, int ok, const struct sockaddr *sa,
                               socklen_t salen, int socktype, int proto, const char *err);

tri_resolve *tri_resolve_start(tri_core *c, const char *host, const char *port,
                               int socktype, tri_resolve_cb cb, void *ud);

void tri_resolve_cancel(tri_resolve *r);

#endif
