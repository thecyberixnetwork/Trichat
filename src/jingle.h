#ifndef TRICHAT_JINGLE_H
#define TRICHAT_JINGLE_H
#include <stddef.h>

#define JINGLE_MAX_CAND 16
#define JINGLE_MAX_PT    8

typedef enum {
    JINGLE_ENDED = 0,
    JINGLE_INCOMING,
    JINGLE_OUTGOING,
    JINGLE_ACTIVE
} jingle_state;

typedef struct {
    int  id;
    char name[24];
    int  clockrate;
    int  channels;
} jingle_payload;

typedef struct {
    char foundation[16];
    int  component;
    char ip[46];
    int  port;
    int  priority;
    char type[12];
    char protocol[8];
} jingle_candidate;

typedef struct {
    jingle_state state;
    char sid[48];
    char peer[128];
    char initiator[128];
    char content_name[32];

    jingle_payload pts[JINGLE_MAX_PT];
    int  npt;

    int  has_video;
    int  video_first;
    char video_name[32];
    jingle_payload vpts[JINGLE_MAX_PT];
    int  nvpt;
    unsigned vssrc;

    char ufrag[72];
    char pwd[128];
    jingle_candidate cand[JINGLE_MAX_CAND];
    int  ncand;

    char setup[12];
    char fp_hash[12];
    char fingerprint[160];

    unsigned ssrc;
    char cname[32];
} jingle_session;

int jingle_parse(const char *stanza, jingle_session *s, char *action, size_t action_sz);

int jingle_build_initiate(char *out, size_t osz, const char *from, const jingle_session *s, const char *iq_id);
int jingle_build_accept(char *out, size_t osz, const char *from, const jingle_session *s, const char *iq_id);
int jingle_build_terminate(char *out, size_t osz, const char *from, const jingle_session *s, const char *reason, const char *iq_id);

int jingle_build_transport_info(char *out, size_t osz, const char *from, const jingle_session *s, const char *iq_id);

int jingle_selftest(void);

#endif
