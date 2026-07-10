#ifndef TRICHAT_HTTP_H
#define TRICHAT_HTTP_H

#include "trichat.h"
#include <sys/select.h>

int  tri_http_fdset(tri_core *c, fd_set *r, fd_set *w);

void tri_http_service(tri_core *c, fd_set *r, fd_set *w);

void tri_http_shutdown(tri_core *c);

#endif
