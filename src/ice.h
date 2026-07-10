#ifndef TRICHAT_ICE_H
#define TRICHAT_ICE_H
#include <stdint.h>
#include <stddef.h>

#define ICE_MAX_CAND 12

typedef struct {
    char     foundation[16];
    int      component;
    char     ip[46];
    int      port;
    unsigned priority;
    char     type[12];
} ice_cand;

typedef struct ice_agent ice_agent;

ice_agent *ice_new(int controlling);
void       ice_free(ice_agent *g);
int        ice_fd(const ice_agent *g);
const char *ice_ufrag(const ice_agent *g);
const char *ice_pwd(const ice_agent *g);

void ice_set_turn(ice_agent *g, const char *turn_ip, int turn_port,
                  const char *user, const char *pass, const char *realm);

int  ice_gather(ice_agent *g, const char *stun_ip, int stun_port);
int  ice_gathering(const ice_agent *g);

int  ice_on_readable(ice_agent *g);
int  ice_tick(ice_agent *g, double now);

int  ice_candidate_count(const ice_agent *g);
int  ice_candidate_get(const ice_agent *g, int i, ice_cand *out);

enum { ICE_NEW = 0, ICE_CHECKING, ICE_CONNECTED, ICE_FAILED };
void ice_set_remote_creds(ice_agent *g, const char *ufrag, const char *pwd);
int  ice_add_remote(ice_agent *g, const char *ip, int port, unsigned priority, const char *type);
void ice_start_checks(ice_agent *g);
int  ice_state(const ice_agent *g);
int  ice_selected(const ice_agent *g, ice_cand *local, ice_cand *remote);

int  ice_send(ice_agent *g, const uint8_t *data, int len);
void ice_set_app_cb(ice_agent *g, void (*cb)(void *ud, const uint8_t *data, int len), void *ud);

void ice_debug(const ice_agent *g, char *out, size_t n);

int  ice_selftest(void);

#endif
