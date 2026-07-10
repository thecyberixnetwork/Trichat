#ifndef TRICHAT_H
#define TRICHAT_H

#include <stddef.h>
#include <stdint.h>

typedef struct tri_core  tri_core;
typedef struct account   account_t;
typedef struct tri_folder tri_folder_t;

enum { TRI_TRUST_UNTRUSTED = -1, TRI_TRUST_UNDECIDED = 0, TRI_TRUST_TRUSTED = 1 };
typedef struct { unsigned device_id; char fingerprint[65]; int trust; } tri_omemo_device_t;

typedef struct {
    const char *name;
    int  (*connect)(account_t *acct);
    void (*disconnect)(account_t *acct);
    int  (*send_message)(account_t *acct, const char *target, const char *body);
    void (*join)(account_t *acct, const char *target);
    void (*leave)(account_t *acct, const char *target);
    void (*on_socket_readable)(account_t *acct, int fd);
    void (*on_socket_writable)(account_t *acct, int fd);
    void (*tick)(account_t *acct);
    int  (*play_file)(account_t *acct, const char *path);
    int  (*mic)(account_t *acct, int on);
    int  (*raw)(account_t *acct, const char *line);
    int  (*send_action)(account_t *acct, const char *target, const char *body);
    int  (*upload)(account_t *acct, const char *target, const char *filepath);

    int  (*upload_relay)(account_t *via, const char *filepath, const char *deliver_key, const char *deliver_target);
    int  (*upload_ready)(account_t *acct);

    int  (*react)(account_t *acct, const char *target, const char *id, const char *emoji);
    int  (*correct)(account_t *acct, const char *target, const char *newbody);

    int  (*moderate)(account_t *acct, const char *channel, const char *user,
                     const char *action, const char *arg);

    int  (*user_info)(account_t *acct, const char *channel, const char *user);

    int  (*record)(account_t *acct, const char *dir);

    int  (*call)(account_t *acct, const char *target, int action);

    int  (*call_peers)(account_t *acct, const char *room, void *out, int cap);
    int  (*call_peer_mute)(account_t *acct, const char *room, const char *full, int muted);

    int  (*is_group)(account_t *acct, const char *target);

    void (*typing)(account_t *acct, const char *target, int composing);

    int  (*omemo_own_fingerprint)(account_t *acct, char *out, size_t n);
    int  (*omemo_devices)(account_t *acct, const char *target, tri_omemo_device_t *out, int cap);
    int  (*omemo_set_trust)(account_t *acct, const char *target, unsigned device_id, int trust);
} protocol_backend_t;

typedef enum { TRI_EV_STATUS, TRI_EV_MESSAGE, TRI_EV_ERROR, TRI_EV_ROSTER, TRI_EV_TYPING, TRI_EV_CALL } tri_event_kind;
typedef struct {
    tri_event_kind kind;
    const char *account;
    const char *target;
    const char *text;
    const char *nick;
    long long   timestamp;
    int         encrypted;
    int         history;
    const char *id;
} tri_event_t;

tri_core *tri_core_new(void (*on_event)(void *ud, const tri_event_t *ev), void *ud);
void      tri_core_free(tri_core *c);
void      tri_core_run(tri_core *c);
void      tri_core_step(tri_core *c, int timeout_ms);
account_t *tri_account_next(tri_core *c, account_t *prev);
void      tri_core_quit(tri_core *c);
int       tri_persistence_selftest(void);

int  tri_core_add_fd(tri_core *c, int fd, void (*cb)(void *ud, int fd), void *ud);
void tri_core_remove_fd(tri_core *c, int fd);

account_t *tri_connect(tri_core *c, const char *backend, const char *account_name, const char *config);
account_t *tri_account_find(tri_core *c, const char *account_name);
account_t *tri_account_find_by_key(tri_core *c, const char *key);
int  tri_send(account_t *a, const char *target, const char *body);
int  tri_send_raw(account_t *a, const char *line);
int  tri_send_action(account_t *a, const char *target, const char *body);
int  tri_react(account_t *a, const char *target, const char *id, const char *emoji);
int  tri_correct(account_t *a, const char *target, const char *newbody);
int  tri_upload(account_t *a, const char *target, const char *filepath);

account_t *tri_upload_provider(tri_core *c);
account_t *tri_upload_provider_next(tri_core *c, account_t *prev);
int  tri_upload_cross(account_t *deliver_to, const char *target, const char *filepath, account_t *via);

int  tri_history_replay(account_t *a, const char *target, int max);
int  tri_join(account_t *a, const char *target);
int  tri_leave(account_t *a, const char *target);
int  tri_play(account_t *a, const char *path);
int  tri_mic(account_t *a, int on);
int  tri_record(account_t *a, const char *dir);
int  tri_disconnect(account_t *a);
void tri_account_remove(tri_core *c, account_t *a);

typedef enum { TRI_CS_OFFLINE, TRI_CS_CONNECTING, TRI_CS_ONLINE } tri_conn_state;
tri_conn_state tri_account_state(const account_t *a);
int  tri_account_connect(account_t *a);
void tri_account_set_autoconnect(account_t *a, int on);
int  tri_account_autoconnect(const account_t *a);

void tri_account_set_insecure(account_t *a, int on);
int  tri_account_insecure(const account_t *a);

void tri_user_set_ignored(account_t *a, const char *user, int ignored);
int  tri_user_ignored(const account_t *a, const char *user);

int  tri_typing(account_t *a, const char *target, int composing);
void tri_account_set_faketyping(account_t *a, const char *target);
const char *tri_account_faketyping(const account_t *a);

enum { TRI_CALL_START = 0, TRI_CALL_ACCEPT = 1, TRI_CALL_HANGUP = 2,
       TRI_CALL_VIDEO = 3,
       TRI_CALL_SCREENSHARE = 4,
       TRI_CALL_VIDEO_STOP = 5 };
int  tri_call(account_t *a, const char *target, int action);

enum { TRI_VIDEO_REMOTE = 0, TRI_VIDEO_SELF = 1 };
void tri_call_video_publish(tri_core *c, const char *acctkey, int which, int w, int h, const uint8_t *rgba);

uint8_t *tri_call_video_stage(tri_core *c, const char *acctkey, int which, int w, int h);
void tri_call_video_commit(tri_core *c, const char *acctkey, int which);
const uint8_t *tri_call_video_frame(tri_core *c, const char *acctkey, int which, int *w, int *h, unsigned *gen);
void tri_call_video_clear(tri_core *c, const char *acctkey, int which);

typedef struct {
    char nick[64];
    char full[320];
    int  connected;
    int  has_video;
    int  video_slot;
    int  talking;
    int  muted;
} tri_call_peer_t;

int  tri_call_peers(account_t *a, const char *room, tri_call_peer_t *out, int cap);

int  tri_call_peer_mute(account_t *a, const char *room, const char *full, int muted);

int  tri_moderate(account_t *a, const char *channel, const char *user, const char *action, const char *arg);
int  tri_user_info(account_t *a, const char *channel, const char *user);

void tri_core_set_store(tri_core *c, const char *path);
int  tri_accounts_load(tri_core *c);
const char *tri_default_store_path(void);

tri_folder_t *tri_folder_create(tri_core *core, const char *name, tri_folder_t *parent  );
int           tri_folder_rename(tri_folder_t *f, const char *new_name);
int           tri_folder_move(tri_folder_t *f, tri_folder_t *new_parent  );

typedef enum { TRI_FOLDER_DELETE_CASCADE, TRI_FOLDER_DELETE_PROMOTE } tri_folder_delete_mode_t;
int           tri_folder_delete(tri_folder_t *f, tri_folder_delete_mode_t mode);

typedef enum { TRI_ROOTITEM_ACCOUNT, TRI_ROOTITEM_FOLDER } tri_rootitem_kind_t;
typedef struct { tri_rootitem_kind_t kind; void *ref; } tri_rootitem_t;
int            tri_root_item_count(tri_core *core);
tri_rootitem_t tri_root_item_get(tri_core *core, int index);
int            tri_root_reorder(tri_core *core, int from_index, int to_index);

typedef enum { TRI_ITEM_ACCOUNT, TRI_ITEM_FOLDER, TRI_ITEM_CHANNEL_REF } tri_folder_item_kind_t;
typedef struct {
    tri_folder_item_kind_t kind;
    account_t     *account;
    tri_folder_t  *folder;
    char           acctkey[96];
    char           target[128];
} tri_folder_item_t;
int               tri_folder_item_count(tri_folder_t *f);
tri_folder_item_t tri_folder_item_get(tri_folder_t *f, int index);

int  tri_account_move_to_folder(account_t *a, tri_folder_t *dest  );
tri_folder_t *tri_account_folder(account_t *a);

int  tri_folder_ref_add(tri_folder_t *f, const char *acctkey, const char *target);
int  tri_folder_ref_remove(tri_folder_t *f, const char *acctkey, const char *target);
int  tri_folder_ref_count_for(const char *acctkey, const char *target);
const char *tri_folder_ref_name_for(const char *acctkey, const char *target, int i);

tri_folder_t *tri_folder_find(tri_core *core, const char *name, tri_folder_t *parent);
const char   *tri_folder_name(tri_folder_t *f);

void tri_channel_set_nick(account_t *a, const char *target, const char *nick);
const char *tri_channel_nick(account_t *a, const char *target);
void tri_channel_set_log(account_t *a, const char *target, int mode);
int  tri_channel_log(account_t *a, const char *target);

void tri_channel_set_member(account_t *a, const char *target, int on);
void tri_channel_member_list(account_t *a, char *out, size_t osz);

int  tri_target_is_group(account_t *a, const char *target);

enum { TRI_NOTIFY_ALL = 0, TRI_NOTIFY_MENTIONS = 1, TRI_NOTIFY_MUTE = 2 };
void tri_channel_set_notify(account_t *a, const char *target, int level);
int  tri_channel_notify(account_t *a, const char *target);

void tri_channel_set_encrypt(account_t *a, const char *target, int on);
int  tri_channel_encrypt(account_t *a, const char *target);
int  tri_omemo_own_fingerprint(account_t *a, char *out, size_t n);
int  tri_omemo_devices(account_t *a, const char *target, tri_omemo_device_t *out, int cap);
int  tri_omemo_set_trust(account_t *a, const char *target, unsigned device_id, int trust);
void tri_account_set_log(account_t *a, int mode);
int  tri_account_log(account_t *a);
void tri_log_set_global(tri_core *c, int on);
int  tri_log_global(tri_core *c);

int  tri_rule_add(tri_core *c, const char *pattern, const char *acctkey  , const char *target  );
void tri_rule_remove(tri_core *c, int index);
int  tri_rule_count(tri_core *c);
int  tri_rule_get(tri_core *c, int i, const char **pattern, const char **acctkey, const char **target);
int  tri_inbox_count(tri_core *c);
int  tri_inbox_get(tri_core *c, int i, const char **acctkey, const char **target, const char **nick, const char **text, long long *ts);
void tri_inbox_clear(tri_core *c);

int  tri_saved_add(tri_core *c, const char *acctkey, const char *target, const char *nick, const char *text, long long ts);
void tri_saved_remove(tri_core *c, int index);
int  tri_saved_count(tri_core *c);
int  tri_saved_get(tri_core *c, int i, const char **acctkey, const char **target, const char **nick, const char **text, long long *ts);

enum { TRI_VOICE_TALKING = 1, TRI_VOICE_MUTED = 2, TRI_VOICE_DEAF = 4 };
void tri_roster_upsert(account_t *a, const char *channel, const char *user, int talking);
void tri_roster_remove(account_t *a, const char *user);
void tri_roster_remove_from(account_t *a, const char *channel, const char *user);
void tri_roster_clear_account(account_t *a);
int  tri_roster_count(tri_core *c);
int  tri_roster_get(tri_core *c, int i, const char **acctkey, const char **channel, const char **user, int *talking);

void tri_chantree_upsert(account_t *a, unsigned id, unsigned parent, const char *name);
void tri_chantree_remove(account_t *a, unsigned id);
void tri_chantree_clear_account(account_t *a);
int  tri_chantree_count(tri_core *c);
int  tri_chantree_get(tri_core *c, int i, const char **acctkey, unsigned *id, unsigned *parent, const char **name);

typedef struct tri_audio_sink tri_audio_sink;
void tri_audio_set(tri_core *c, const char *method, const char *device);
void tri_audio_get(tri_core *c, const char **method, const char **device);
void tri_audio_command(tri_core *c, char *out, size_t n);
int  tri_audio_test(tri_core *c);
tri_audio_sink *tri_audio_open(tri_core *c);
tri_audio_sink *tri_audio_open_named(tri_core *c, const char *name);
void tri_audio_write(tri_audio_sink *s, const int16_t *pcm, int samples);
void tri_audio_close(tri_audio_sink *s);

typedef struct tri_audio_source tri_audio_source;
tri_audio_source *tri_audio_capture_open(tri_core *c, const char *device);
int  tri_audio_source_fd(tri_audio_source *s);
int  tri_audio_source_read(tri_audio_source *s, int16_t *pcm, int max_samples);
void tri_audio_capture_close(tri_audio_source *s);

typedef void (*tri_http_cb)(void *ud, int ok, int status, const char *body, size_t len, const char *content_type);
int tri_http_get(tri_core *c, const char *url, tri_http_cb cb, void *ud);
int tri_http_put(tri_core *c, const char *url, const char *content_type, const void *data, size_t len,
                 const char *const *extra_headers, int n_extra, tri_http_cb cb, void *ud);

const char *tri_last_error(void);

void tri_emit(tri_core *c, const tri_event_t *ev);
int  tri_account_fd(const account_t *a);
void tri_account_set_fd(account_t *a, int fd);
void  *tri_account_priv(const account_t *a);
void tri_account_set_priv(account_t *a, void *priv);
const char *tri_account_name(const account_t *a);
const char *tri_account_key(const account_t *a);
const char *tri_account_config(const account_t *a);
const char *tri_account_backend(const account_t *a);
tri_core *tri_account_core(const account_t *a);
void tri_account_set_write_interest(account_t *a, int on);
int  tri_set_error(const char *fmt, ...);
void tri_account_set_state(account_t *a, tri_conn_state s);
void tri_account_notify_down(account_t *a, const char *reason);
void tri_account_notify_failed(account_t *a, const char *reason);
void tri_log(tri_core *c, const char *fmt, ...);

enum { TRI_PIN_NEW = 0, TRI_PIN_MATCH = 1, TRI_PIN_MISMATCH = -1 };
int  tri_tls_pin_check(tri_core *c, const char *host, const char *fp);
void tri_tls_pin_store(tri_core *c, const char *host, const char *fp);

#endif
