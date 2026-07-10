#include "trichat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_event(void *ud, const tri_event_t *ev) {
    (void)ud;
    if (ev->kind == TRI_EV_TYPING) return;
    const char *tag = ev->kind == TRI_EV_ERROR ? "!!" :
                      ev->kind == TRI_EV_MESSAGE ? (ev->history ? "~~" : "<<") : "--";
    char body[1400];
    if (ev->nick && ev->nick[0]) snprintf(body, sizeof body, "<%s> %s", ev->nick, ev->text);
    else                         snprintf(body, sizeof body, "%s", ev->text);
    if (ev->account && !strcmp(ev->account, "*:alert")) fputs("\a", stdout);
    printf("%s [%s%s%s] %s\n", tag,
           ev->account ? ev->account : "core",
           ev->target ? "/" : "", ev->target ? ev->target : "",
           body);
    fflush(stdout);
}

static void fail(tri_core *c) {
    tri_event_t ev = { TRI_EV_ERROR, NULL, NULL, tri_last_error(), NULL, 0 };
    tri_emit(c, &ev);
}

static void print_folder(tri_folder_t *f, int depth) {
    char pad[32]; int n = depth * 2; if (n > 30) n = 30;
    memset(pad, ' ', n); pad[n] = '\0';
    for (int i = 0; i < tri_folder_item_count(f); i++) {
        tri_folder_item_t it = tri_folder_item_get(f, i);
        if (it.kind == TRI_ITEM_ACCOUNT)
            printf("%s  * %s\n", pad, tri_account_key(it.account));
        else if (it.kind == TRI_ITEM_FOLDER)
            { printf("%s  [%s]\n", pad, tri_folder_name(it.folder)); print_folder(it.folder, depth + 1); }
        else
            printf("%s  -> %s / %s\n", pad, it.acctkey, it.target);
    }
}
static void print_folder_tree(tri_core *c) {
    for (int i = 0; i < tri_root_item_count(c); i++) {
        tri_rootitem_t r = tri_root_item_get(c, i);
        if (r.kind == TRI_ROOTITEM_FOLDER) {
            tri_folder_t *f = r.ref;
            printf("-- folder '%s':\n", tri_folder_name(f));
            print_folder(f, 0);
        }
    }
}

static void on_stdin(void *ud, int fd) {
    (void)fd;
    tri_core *c = ud;
    char line[1024];
    if (!fgets(line, sizeof line, stdin)) { tri_core_quit(c); return; }
    line[strcspn(line, "\n")] = '\0';

    char *cmd = strtok(line, " ");
    if (!cmd || !*cmd) return;

    if (!strcmp(cmd, "connect")) {
        char *backend = strtok(NULL, " "), *name = strtok(NULL, " "), *config = strtok(NULL, "");
        if (!backend || !name) { tri_set_error("usage: connect <backend> <account> [config]"); fail(c); return; }
        if (!tri_connect(c, backend, name, config)) fail(c);
    } else if (!strcmp(cmd, "send")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " "), *body = strtok(NULL, "");
        if (!acct || !target || !body) { tri_set_error("usage: send <account> <target> <message>"); fail(c); return; }
        account_t *a = tri_account_find(c, acct);
        if (!a) { tri_set_error("no such account '%s'", acct); fail(c); return; }
        if (tri_send(a, target, body) != 0) fail(c);
    } else if (!strcmp(cmd, "join") || !strcmp(cmd, "part")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " ");
        if (!acct || !target) { tri_set_error("usage: %s <account> <target>", cmd); fail(c); return; }
        account_t *a = tri_account_find(c, acct);
        if (!a) { tri_set_error("no such account '%s'", acct); fail(c); return; }
        int rc = cmd[0] == 'j' ? tri_join(a, target) : tri_leave(a, target);
        if (rc != 0) fail(c);
    } else if (!strcmp(cmd, "play")) {
        char *acct = strtok(NULL, " "), *path = strtok(NULL, "");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a || !path) { tri_set_error("usage: play <account> <file.wav>"); fail(c); return; }
        if (tri_play(a, path) != 0) fail(c);
    } else if (!strcmp(cmd, "mic")) {
        char *acct = strtok(NULL, " "), *st = strtok(NULL, " ");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a) { tri_set_error("usage: mic <account> [on|off]"); fail(c); return; }
        if (tri_mic(a, !st || strcmp(st, "off")) != 0) fail(c);
    } else if (!strcmp(cmd, "call") || !strcmp(cmd, "accept") || !strcmp(cmd, "hangup")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " ");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        int act = cmd[0] == 'c' ? TRI_CALL_START : cmd[0] == 'a' ? TRI_CALL_ACCEPT : TRI_CALL_HANGUP;
        if (!a || (act == TRI_CALL_START && !target)) { tri_set_error("usage: %s <account>%s", cmd, act == TRI_CALL_START ? " <jid>" : ""); fail(c); return; }
        if (tri_call(a, target, act) != 0) fail(c);
    } else if (!strcmp(cmd, "video") || !strcmp(cmd, "screenshare") || !strcmp(cmd, "stopvideo")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " ");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        int act = !strcmp(cmd, "screenshare") ? TRI_CALL_SCREENSHARE : !strcmp(cmd, "video") ? TRI_CALL_VIDEO : TRI_CALL_VIDEO_STOP;
        if (!a || (act != TRI_CALL_VIDEO_STOP && !target)) { tri_set_error("usage: %s <account> <jid>", cmd); fail(c); return; }
        if (tri_call(a, target, act) != 0) fail(c);
    } else if (!strcmp(cmd, "folder")) {
        char *name = strtok(NULL, " "), *parent = strtok(NULL, " ");
        if (!name) { tri_set_error("usage: folder <name> [parent]"); fail(c); return; }
        tri_folder_t *p = parent ? tri_folder_find(c, parent, NULL) : NULL;
        if (parent && !p) { tri_set_error("no root folder named '%s'", parent); fail(c); return; }
        if (!tri_folder_create(c, name, p)) fail(c);
    } else if (!strcmp(cmd, "file") || !strcmp(cmd, "unfile")) {
        char *fname = strtok(NULL, " "), *acct = strtok(NULL, " "), *target = strtok(NULL, " ");
        if (!fname || !acct || !target) { tri_set_error("usage: %s <folder> <account-key> <target>", cmd); fail(c); return; }
        tri_folder_t *f = tri_folder_find(c, fname, NULL);
        if (!f) { tri_set_error("no root folder named '%s'", fname); fail(c); return; }
        if (cmd[0] == 'f') tri_folder_ref_add(f, acct, target);
        else tri_folder_ref_remove(f, acct, target);
    } else if (!strcmp(cmd, "move")) {
        char *acct = strtok(NULL, " "), *fname = strtok(NULL, " ");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a) { tri_set_error("usage: move <account> [folder]"); fail(c); return; }
        tri_folder_t *f = fname ? tri_folder_find(c, fname, NULL) : NULL;
        if (fname && !f) { tri_set_error("no root folder named '%s'", fname); fail(c); return; }
        tri_account_move_to_folder(a, f);
    } else if (!strcmp(cmd, "audio")) {
        char *method = strtok(NULL, " "), *device = strtok(NULL, "");
        if (method) tri_audio_set(c, method, device);
        char resolved[512]; tri_audio_command(c, resolved, sizeof resolved);
        printf("-- audio command: %s\n", resolved[0] ? resolved : "(none found)");
        if (tri_audio_test(c) != 0) fail(c); else printf("-- played test tone\n");
        fflush(stdout);
    } else if (!strcmp(cmd, "roster")) {
        for (int i = 0; i < tri_roster_count(c); i++) {
            const char *ak = NULL, *ch = NULL, *us = NULL; int tk = 0; tri_roster_get(c, i, &ak, &ch, &us, &tk);
            printf("     [%s] %s / %s%s\n", ak, ch, us, tk ? " (talking)" : "");
        }
        fflush(stdout);
    } else if (!strcmp(cmd, "folders")) {
        print_folder_tree(c);
        fflush(stdout);
    } else if (!strcmp(cmd, "remove")) {
        char *acct = strtok(NULL, " ");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a) { tri_set_error("usage: remove <account>"); fail(c); return; }
        tri_account_remove(c, a);
    } else if (!strcmp(cmd, "nick")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " "), *nick = strtok(NULL, "");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a || !target) { tri_set_error("usage: nick <account> <target> [nickname]  (empty clears)"); fail(c); return; }
        tri_channel_set_nick(a, target, nick);
        printf("-- nick for %s/%s = '%s'\n", tri_account_key(a), target, tri_channel_nick(a, target)); fflush(stdout);
    } else if (!strcmp(cmd, "log")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " "), *mode = strtok(NULL, " ");
        if (acct && !strcmp(acct, "global")) {
            if (target) tri_log_set_global(c, !strcmp(target, "on"));
            printf("-- global logging: %s\n", tri_log_global(c) ? "on" : "off"); fflush(stdout); return;
        }
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a || !target || !mode) { tri_set_error("usage: log <account> <target> on|off|inherit  |  log <account> all on|off  |  log global on|off"); fail(c); return; }
        int m = !strcmp(mode, "on") ? 1 : !strcmp(mode, "off") ? 0 : -1;
        if (!strcmp(target, "all")) { tri_account_set_log(a, m); printf("-- log %s (all channels): %s\n", tri_account_key(a), m < 0 ? "inherit" : m ? "on" : "off"); }
        else { tri_channel_set_log(a, target, m); printf("-- log %s/%s: effective %s\n", tri_account_key(a), target, tri_channel_log(a, target) ? "on" : "off"); }
        fflush(stdout);
    } else if (!strcmp(cmd, "alert")) {
        char *sub = strtok(NULL, " ");
        if (sub && !strcmp(sub, "add")) {
            char *pat = strtok(NULL, "");
            if (!pat) { tri_set_error("usage: alert add <pattern>"); fail(c); return; }
            if (tri_rule_add(c, pat, NULL, NULL) != 0) fail(c);
        } else if (sub && !strcmp(sub, "del")) {
            char *n = strtok(NULL, " "); tri_rule_remove(c, n ? atoi(n) : -1);
        } else {
            for (int i = 0; i < tri_rule_count(c); i++) {
                const char *pat = NULL, *ak = NULL, *tg = NULL; tri_rule_get(c, i, &pat, &ak, &tg);
                printf("     [%d] '%s' %s%s%s\n", i, pat, ak[0] ? ak : "*", tg[0] ? "/" : "", tg);
            }
            fflush(stdout);
        }
    } else if (!strcmp(cmd, "inbox")) {
        char *sub = strtok(NULL, " ");
        if (sub && !strcmp(sub, "clear")) { tri_inbox_clear(c); return; }
        for (int i = 0; i < tri_inbox_count(c); i++) {
            const char *ak = NULL, *tg = NULL, *nk = NULL, *tx = NULL; long long ts = 0;
            tri_inbox_get(c, i, &ak, &tg, &nk, &tx, &ts);
            printf("     [%s/%s] <%s> %s\n", ak, tg, nk, tx);
        }
        fflush(stdout);
    } else if (!strcmp(cmd, "history")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " "), *n = strtok(NULL, " ");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a || !target) { tri_set_error("usage: history <account> <target> [count]"); fail(c); return; }
        int got = tri_history_replay(a, target, n ? atoi(n) : 0);
        if (got < 0) fail(c); else { printf("-- replayed %d line(s)\n", got); fflush(stdout); }
    } else if (!strcmp(cmd, "attach")) {
        char *acct = strtok(NULL, " "), *target = strtok(NULL, " "), *path = strtok(NULL, "");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a || !target || !path) { tri_set_error("usage: attach <account> <target> <path>"); fail(c); return; }

        if (tri_upload(a, target, path) != 0) {
            account_t *via = tri_upload_provider(c);
            if (!via) { fail(c); return; }
            if (tri_upload_cross(a, target, path, via) != 0) fail(c);
            else printf("-- uploading via %s\n", tri_account_key(via)), fflush(stdout);
        }
    } else if (!strcmp(cmd, "record")) {
        char *acct = strtok(NULL, " "), *dir = strtok(NULL, "");
        account_t *a = acct ? tri_account_find(c, acct) : NULL;
        if (!a) { tri_set_error("usage: record <account> <dir>  |  record <account> off"); fail(c); return; }
        if (tri_record(a, (dir && strcmp(dir, "off")) ? dir : NULL) != 0) fail(c);
    } else if (!strcmp(cmd, "quit")) {
        tri_core_quit(c);
    } else {
        tri_set_error("unknown command '%s' (try: connect, send, join, part, call, accept, hangup, play, record, history, attach, folder, file, unfile, move, folders, nick, log, alert, inbox, remove, quit)", cmd);
        fail(c);
    }
}

int main(int argc, char **argv) {
    tri_core *c = tri_core_new(print_event, NULL);
    if (!c) { fprintf(stderr, "trichat: %s\n", tri_last_error()); return 1; }
    if (tri_core_add_fd(c, 0, on_stdin, c) != 0) {
        fprintf(stderr, "trichat: %s\n", tri_last_error()); return 1;
    }
    if (argc > 1 && !strcmp(argv[1], "--persist")) {
        tri_core_set_store(c, tri_default_store_path());
        int n = tri_accounts_load(c);
        printf("trichat: restored %d saved account(s)\n", n);
    }
    printf("trichat cli - commands: connect <backend> <account> [cfg] | send <a> <t> <msg> | join/part <a> <t> | call/accept/hangup <a> [jid] | video/screenshare <a> <jid> | mic <a> [on|off] | play <a> <file.wav> | remove <a> | quit\n");
    fflush(stdout);
    tri_core_run(c);
    tri_core_free(c);
    return 0;
}
