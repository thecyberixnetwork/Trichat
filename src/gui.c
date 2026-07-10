#include "trichat.h"
#include "util.h"
#include <iup.h>
#include <iupdraw.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

static tri_core *core;
static int core_alive = 1;
static Ihandle *dlg, *tree, *tabs, *input, *members, *attach, *attachbar, *attach_clear, *typing_lbl, *omemo_toggle;

static Ihandle *hdr_title, *hdr_status, *mempanel;
static void chrome_sync(void);

static Ihandle *replybar, *reply_preview;
static char g_reply_nick[64], g_reply_text[400];
static void reply_clear(void);
static void reply_begin(const char *nick, const char *body);

enum { VIT_MSG, VIT_SELF, VIT_STATUS, VIT_ERROR };

enum { MED_PENDING, MED_LOADED, MED_FAILED };
typedef struct media {
    struct media *next;
    Ihandle *canvas;
    Ihandle *img;
    unsigned char *pixels;
    int orphan, state;
    unsigned uid;
    char url[1024], path[600], imgname[40];
    int w, h;
    int rx, ry, rw, rh;
} media_t;

#define VIT_MEDIA 4
typedef struct { long long ts; int kind; char nick[64]; char *body; media_t *media[VIT_MEDIA]; int nmedia; int highlight; unsigned char encrypted; } vitem_t;

#define VIT_CAP   2000
#define VLINK_CAP 128

typedef struct { int x, y, w, h; char url[512]; } vlink_t;

#define ATTACH_MAX 32
typedef struct {
    char acct[96], target[128];
    Ihandle *tab;
    char attach[ATTACH_MAX][600];
    int  nattach;
    vitem_t *items;
    int nit;

    int lay_w;
    int *item_h;
    int total_h, line_h, indent;
    int nick_col;
    int cw, ch;
    int posy;
    int stick;
    vlink_t *links;
    int nlinks;
    struct { int x, y, w, h; media_t *m; } mhits[32];
    int nmhit;

    int sel_on, dragging;
    int a_item, a_off;
    int c_item, c_off;
    int press_x, press_y;
    int unread;
    int unread_at;
    int pending_unread_scroll;
    int seek_to;
    char typing_nick[64];
    long long typing_at;
    char draft[1400];
    int history_loaded;
    char last_msgid[64];
    int group_latch;
} view_t;
static view_t views[256];
static int nviews;
static view_t *current;

static Ihandle *attachrow, *attachscroll;
static void queue_add(const char *path);
static void queue_flush(void);
static void attachbar_refresh(void);

#define ERRORS_KEY "*:errors"
#define DEBUG_KEY  "*:debug"

#define INBOX_KEY  "*:alert"

#define SAVED_KEY  "*:saved"

static media_t *g_media;
static media_t *g_ctxmedia;
static char g_mediadir[512];
static int  opt_embed = 1;
static int  opt_purge = 1;

static void view_refresh_members(void);
static void scan_media(view_t *v, vitem_t *it);
static void media_detach(vitem_t *it);
static media_t *media_at(view_t *v, int x, int y);
static void media_open(media_t *m);
static void media_context_menu(void);
static Ihandle *mk(const char *label, Icallback cb);
static void on_event(void *ud, const tri_event_t *ev);
static void switch_to(view_t *v);
static void mark_read(view_t *v);
static view_t *inbox_view(void);
static view_t *saved_view(void);
static void saved_view_add(const char *acctkey, const char *target, const char *nick, const char *text, long long ts);

static const char *key_name(const char *key) { const char *c = strchr(key, ':'); return c ? c + 1 : key; }

enum { NODE_ACCOUNT, NODE_FOLDERACCT, NODE_CHANNEL, NODE_FOLDER, NODE_FOLDERCHANREF, NODE_INBOX, NODE_SAVED };
static struct {
    int node, kind, parent, branch;
    view_t *v;
    account_t *account;
    tri_folder_t *folder;
    char acctkey[96], target[128];
} nodemap[512];
static int nnodemap;
static void nodemap_add(int node, int kind, int parent, int branch, view_t *v,
                        account_t *account, tri_folder_t *folder, const char *acctkey, const char *target) {
    if (nnodemap >= 512) return;
    nodemap[nnodemap].node = node; nodemap[nnodemap].kind = kind;
    nodemap[nnodemap].parent = parent; nodemap[nnodemap].branch = branch;
    nodemap[nnodemap].v = v; nodemap[nnodemap].account = account; nodemap[nnodemap].folder = folder;
    snprintf(nodemap[nnodemap].acctkey, 96, "%s", acctkey ? acctkey : "");
    snprintf(nodemap[nnodemap].target, 128, "%s", target ? target : "");
    nnodemap++;
}
static int nodemap_find(int node) { for (int i = 0; i < nnodemap; i++) if (nodemap[i].node == node) return i; return -1; }

static view_t *view_find(const char *acct, const char *target) {
    for (int i = 0; i < nviews; i++)
        if (!strcmp(views[i].acct, acct) && !strcmp(views[i].target, target))
            return &views[i];
    return NULL;
}
static view_t *view_by_canvas(Ihandle *c) {
    if (!c) return NULL;
    for (int i = 0; i < nviews; i++) if (views[i].tab == c) return &views[i];
    return NULL;
}

struct pal {
    const char *ts, *self, *stat, *err, *link, *sel, *ment, *div, *quote, *enc;
    const char *const *nick; int nnick;
};
static const char *const NICK_LIGHT[] = {
    "192 57 43","41 128 185","39 174 96","142 68 173","211 84 0",
    "22 160 133","41 62 120","217 30 120","243 156 18","108 122 137" };
static const char *const NICK_DARK[] = {
    "231 111 81","93 173 226","88 214 141","187 143 206","240 142 74",
    "72 201 176","124 145 220","240 98 176","247 202 96","171 183 193" };
static const struct pal PAL_LIGHT = {
    "130 130 130","58 104 168","120 120 120","192 57 43","40 90 200",
    "180 205 255","255 245 200","216 100 100","17 122 51","60 160 90",
    NICK_LIGHT, (int)(sizeof NICK_LIGHT / sizeof *NICK_LIGHT) };
static const struct pal PAL_DARK = {
    "150 150 150","120 170 240","140 140 140","231 111 81","110 160 250",
    "40 70 110","70 66 40","216 100 100","120 200 120","90 200 130",
    NICK_DARK, (int)(sizeof NICK_DARK / sizeof *NICK_DARK) };

static struct { char bg[16], body[16]; const struct pal *p; } TH;
#define CBG    TH.bg
#define CBODY  TH.body
#define CTS    TH.p->ts
#define CSELF  TH.p->self
#define CSTAT  TH.p->stat
#define CERR   TH.p->err
#define CLINK  TH.p->link
#define CSEL   TH.p->sel
#define CMENT  TH.p->ment
#define CDIV   TH.p->div
#define CQUOTE TH.p->quote
#define CENC   TH.p->enc
static const char *nick_color(const char *n) {
    unsigned h = 5381; for (const char *p = n; *p; p++) h = h * 33u + (unsigned char)*p;
    return TH.p->nick[h % TH.p->nnick];
}
static char g_fontstr[3][40];
static int g_bold;
static double g_uiscale = 1.0;
static void set_color(Ihandle *c, const char *rgb) { IupSetStrAttribute(c, "DRAWCOLOR", rgb); }

static void set_font(Ihandle *c, int bold) { g_bold = bold;
    IupSetStrAttribute(c, "DRAWFONT", g_fontstr[bold]); }

static void ui_theme_init(void) {
    const struct pal *p = &PAL_LIGHT;
    strcpy(TH.bg, "255 255 255"); strcpy(TH.body, "30 30 30");
    GtkWidget *w = gtk_text_view_new();
    if (w) {
        g_object_ref_sink(w);
        GtkStyleContext *ctx = gtk_widget_get_style_context(w);
        gtk_style_context_add_class(ctx, GTK_STYLE_CLASS_VIEW);
        GdkRGBA fg, bg;
        gtk_style_context_get_color(ctx, GTK_STATE_FLAG_NORMAL, &fg);
        gtk_style_context_get_background_color(ctx, GTK_STATE_FLAG_NORMAL, &bg);
        double lum = 0.299 * fg.red + 0.587 * fg.green + 0.114 * fg.blue;
        if (lum > 0.5) p = &PAL_DARK;
        snprintf(TH.body, sizeof TH.body, "%d %d %d",
                 (int)(fg.red * 255), (int)(fg.green * 255), (int)(fg.blue * 255));
        if (bg.alpha > 0.1)
            snprintf(TH.bg, sizeof TH.bg, "%d %d %d",
                     (int)(bg.red * 255), (int)(bg.green * 255), (int)(bg.blue * 255));
        else if (p == &PAL_DARK)
            strcpy(TH.bg, "45 45 45");
        g_object_unref(w);
    }
    TH.p = p;
    int pt = 0;
    const char *e = getenv("TRICHAT_FONT");
    if (e) pt = atoi(e);
    if (pt <= 0) {
        GdkScreen *scr = gdk_screen_get_default();
        double res = scr ? gdk_screen_get_resolution(scr) : -1;
        if (res > 0) g_uiscale = res / 96.0;
        pt = (int)(9.0 * g_uiscale + 0.5);
    } else g_uiscale = pt / 9.0;
    if (pt < 6) { pt = 9; g_uiscale = 1.0; }
    snprintf(g_fontstr[0], sizeof g_fontstr[0], "Sans %d", pt);
    snprintf(g_fontstr[1], sizeof g_fontstr[1], "Sans Bold %d", pt);
    snprintf(g_fontstr[2], sizeof g_fontstr[2], "Monospace %d", pt);
}

static const char *rsz(const char *wh) {
    static char buf[32];
    const char *x = strchr(wh, 'x');
    if (!x) { snprintf(buf, sizeof buf, "%s", wh); return buf; }
    char wp[12] = "", hp[12] = "";
    if (x != wh)  snprintf(wp, sizeof wp, "%d", (int)(atoi(wh)    * g_uiscale + 0.5));
    if (x[1])     snprintf(hp, sizeof hp, "%d", (int)(atoi(x + 1) * g_uiscale + 0.5));
    snprintf(buf, sizeof buf, "%sx%s", wp, hp);
    return buf;
}

#define TWC_BITS 13
#define TWC_SZ   (1 << TWC_BITS)
#define TWC_MAXLEN 48
static struct { int len, bold, w; char s[TWC_MAXLEN]; } g_twc[TWC_SZ];
static long g_textmeasures;
static int text_w(Ihandle *c, const char *s, int len) {
    if (len <= 0) return 0;
    if (len < TWC_MAXLEN) {
        unsigned h = 2166136261u;
        for (int i = 0; i < len; i++) h = (h ^ (unsigned char)s[i]) * 16777619u;
        unsigned slot = (h ^ (unsigned)(g_bold * 0x9e3779b1u)) & (TWC_SZ - 1);
        if (g_twc[slot].len == len && g_twc[slot].bold == g_bold && !memcmp(g_twc[slot].s, s, len))
            return g_twc[slot].w;
        int w = 0, ht = 0; g_textmeasures++; IupDrawGetTextSize(c, s, len, &w, &ht);
        g_twc[slot].len = len; g_twc[slot].bold = g_bold; g_twc[slot].w = w; memcpy(g_twc[slot].s, s, len);
        return w;
    }
    int w = 0, h = 0; g_textmeasures++; IupDrawGetTextSize(c, s, len, &w, &h); return w;
}
static int is_url(const char *w, int len) { return (len > 8 && !strncmp(w, "https://", 8)) || (len > 7 && !strncmp(w, "http://", 7)); }

static int utf8len(const char *p) { unsigned char b = (unsigned char)*p;
    if (b < 0x80) return 1; if ((b >> 5) == 0x6) return 2; if ((b >> 4) == 0xe) return 3; if ((b >> 3) == 0x1e) return 4; return 1; }

static int body_is_pre(const char *s) {
    int run = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '\t') return 1;
        if (*p == ' ') { if (++run >= 3) return 1; } else run = 0;
    }
    return 0;
}
#define LOCK_GLYPH "\xF0\x9F\x94\x92 "

static int g_hit_on, g_hit_item, g_hit_x, g_hit_y, g_hit_off; long g_hit_best;
static void hit_seg(Ihandle *c, const char *str, int len, int base, int sx, int sy, int lh) {
    if (!g_hit_on || len <= 0) return;
    int segw = text_w(c, str, len);
    int dy = g_hit_y < sy ? sy - g_hit_y : g_hit_y >= sy + lh ? g_hit_y - (sy + lh - 1) : 0;
    int dx = g_hit_x < sx ? sx - g_hit_x : g_hit_x >= sx + segw ? g_hit_x - (sx + segw - 1) : 0;
    long score = (long)dy * 100000 + dx;
    if (g_hit_best >= 0 && score >= g_hit_best) return;
    g_hit_best = score;
    int off = base + len;
    if (g_hit_x <= sx) off = base;
    else for (int i = 0; i < len; i++) {
        int wl = text_w(c, str, i), wr = text_w(c, str, i + 1);
        if (g_hit_x < sx + wr) { off = base + (g_hit_x >= sx + (wl + wr) / 2 ? i + 1 : i); break; }
    }
    g_hit_off = off;
}

static void sel_range(view_t *v, int *s_item, int *s_off, int *e_item, int *e_off) {
    int ai = v->a_item, ao = v->a_off, ci = v->c_item, co = v->c_off;
    if (ai < ci || (ai == ci && ao <= co)) { *s_item = ai; *s_off = ao; *e_item = ci; *e_off = co; }
    else                                    { *s_item = ci; *s_off = co; *e_item = ai; *e_off = ao; }
}

static void sel_span_for(view_t *v, int item, int *lo, int *hi) {
    if (!v->sel_on) { *lo = *hi = -1; return; }
    int si, so, ei, eo; sel_range(v, &si, &so, &ei, &eo);
    if (item < si || item > ei) { *lo = *hi = -1; return; }
    *lo = (item == si) ? so : 0;
    *hi = (item == ei) ? eo : 1 << 30;
}

static void draw_seg(Ihandle *c, const char *str, int len, int base_off,
                     int x, int y, int lh, const char *color, int sel_lo, int sel_hi) {
    if (len <= 0) return;
    if (sel_lo >= 0) {
        int lo = sel_lo - base_off, hi = sel_hi - base_off;
        if (lo < 0) lo = 0; if (hi > len) hi = len;
        if (lo < hi) {
            int x0 = x + text_w(c, str, lo), x1 = x + text_w(c, str, hi);
            set_color(c, CSEL); IupSetAttribute(c, "DRAWSTYLE", "FILL"); IupDrawRectangle(c, x0, y, x1, y + lh);
        }
    }
    set_color(c, color); IupDrawText(c, str, len, x, y, text_w(c, str, len), lh);
}

static int layout_item(view_t *v, Ihandle *c, int idx, int W, int y, int draw) {
    vitem_t *it = &v->items[idx];
    int lh = v->line_h, spw = text_w(c, " ", 1);
    const char *bodyc = it->kind == VIT_ERROR ? CERR : it->kind == VIT_STATUS ? CSTAT : CBODY;
    char ts[48], tsraw[24]; time_t tt = (time_t)it->ts; struct tm *lt = localtime(&tt);
    strftime(tsraw, sizeof tsraw, "[%H:%M] ", lt);
    snprintf(ts, sizeof ts, "%s%s", it->encrypted ? LOCK_GLYPH : "", tsraw);
    const char *tscol = it->encrypted ? CENC : CTS;
    int sel_lo, sel_hi; sel_span_for(v, idx, &sel_lo, &sel_hi);

    if (draw && it->highlight) { set_color(c, CMENT); IupSetAttribute(c, "DRAWSTYLE", "FILL");
                                 int hh = v->item_h ? v->item_h[idx] : lh; IupDrawRectangle(c, 0, y, W, y + hh); }

    int is_msg = (it->kind == VIT_MSG || it->kind == VIT_SELF);
    int pre = body_is_pre(it->body);
    int x = 0, coff = 0;
    set_font(c, 0);
    int tsw = text_w(c, ts, (int)strlen(ts));
    if (draw) draw_seg(c, ts, (int)strlen(ts), coff, x, y, lh, tscol, sel_lo, sel_hi);
    hit_seg(c, ts, (int)strlen(ts), coff, x, y, lh);
    coff += (int)strlen(ts);

    int bodyx, cont;
    if (is_msg) {
        const char *nc = it->kind == VIT_SELF ? CSELF : nick_color(it->nick);
        int nlen = (int)strlen(it->nick);
        set_font(c, 1);
        int nw = text_w(c, it->nick, nlen);
        set_font(c, 0);
        int sw = text_w(c, ": ", 2);

        int col = v->nick_col > nw ? v->nick_col : nw;
        int nickx = tsw + (col - nw);
        int sepx = nickx + nw;
        set_font(c, 1);
        if (draw) draw_seg(c, it->nick, nlen, coff, nickx, y, lh, nc, sel_lo, sel_hi);
        hit_seg(c, it->nick, nlen, coff, nickx, y, lh);
        set_font(c, 0);
        coff += nlen;
        if (draw) draw_seg(c, ": ", 2, coff, sepx, y, lh, bodyc, sel_lo, sel_hi);
        hit_seg(c, ": ", 2, coff, sepx, y, lh);
        coff += 2;
        bodyx = sepx + sw;
        cont = bodyx;
    } else {
        bodyx = tsw;
        cont = tsw;
    }
    x = bodyx;
    int curx = x, yy = y, base_body = coff, bc = 0;
    if (pre) {
        set_font(c, 2);
        for (const char *p = it->body; *p; ) {
            if (*p == '\n') { yy += lh; curx = cont; bc++; p++; continue; }
            if (*p == '\r') { bc++; p++; continue; }
            int cl = utf8len(p), cw = text_w(c, p, cl);
            if (curx + cw > W && curx > cont) { yy += lh; curx = cont; }
            hit_seg(c, p, cl, base_body + bc, curx, yy, lh);
            if (draw) draw_seg(c, p, cl, base_body + bc, curx, yy, lh, bodyc, sel_lo, sel_hi);
            curx += cw; bc += cl; p += cl;
        }
    } else {
    int line_start = x, first = 1, seg_quote = 0;
    for (const char *p = it->body; *p; ) {
        int hardbreak = 0;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') { if (*p == '\n') hardbreak = 1; p++; }
        if (!*p) break;
        const char *ws = p; while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        int wlen = (int)(p - ws), tw = text_w(c, ws, wlen);

        if (first || hardbreak) seg_quote = is_msg && *ws == '>';
        const char *segc = seg_quote ? CQUOTE : bodyc;
        if (!first && hardbreak) {
            yy += lh; curx = cont; line_start = cont;
            bc += 1;
        } else {
            int need = (curx > line_start ? spw : 0) + tw;
            if (curx + need > W && curx > line_start) { yy += lh; curx = cont; line_start = cont; }
            if (!first) {
                if (curx > line_start) { if (draw) draw_seg(c, " ", 1, base_body + bc, curx, yy, lh, segc, sel_lo, sel_hi);
                                         hit_seg(c, " ", 1, base_body + bc, curx, yy, lh); curx += spw; }
                bc += 1;
            }
        }
        first = 0;
        int link = is_url(ws, wlen);

        if (!link && curx + tw > W) {
            int qoff = base_body + bc;
            for (const char *q = ws; q < p; ) {
                int cl = utf8len(q), cw = text_w(c, q, cl);
                if (curx + cw > W && curx > line_start) { yy += lh; curx = cont; line_start = cont; }
                hit_seg(c, q, cl, qoff, curx, yy, lh);
                if (draw) draw_seg(c, q, cl, qoff, curx, yy, lh, segc, sel_lo, sel_hi);
                curx += cw; qoff += cl; q += cl;
            }
            bc += wlen;
            continue;
        }
        hit_seg(c, ws, wlen, base_body + bc, curx, yy, lh);
        if (draw) {
            draw_seg(c, ws, wlen, base_body + bc, curx, yy, lh, link ? CLINK : segc, sel_lo, sel_hi);
            if (link) {
                IupDrawLine(c, curx, yy + lh - 2, curx + tw, yy + lh - 2);
                if (v->nlinks < VLINK_CAP) {
                    v->links[v->nlinks].x = curx; v->links[v->nlinks].y = yy;
                    v->links[v->nlinks].w = tw;   v->links[v->nlinks].h = lh;
                    snprintf(v->links[v->nlinks].url, sizeof v->links[v->nlinks].url, "%.*s", wlen, ws);
                    v->nlinks++;
                }
            }
        }
        curx += tw; bc += wlen;
    }
    }
    int texth = (yy - y) + lh, mediah = 0;
    for (int mi = 0; mi < it->nmedia; mi++) {
        media_t *m = it->media[mi];
        int loaded = (m->state == MED_LOADED && m->img);
        int mh = loaded ? m->h : lh, mw = loaded ? m->w : 0;
        int my = y + texth + mediah + 2;
        if (draw) {
            if (loaded) { IupDrawImage(c, m->imgname, cont, my, mw, mh);
                          m->rx = cont; m->ry = my; m->rw = mw; m->rh = mh;
                          if (v->nmhit < 32) { v->mhits[v->nmhit].x = cont; v->mhits[v->nmhit].y = my;
                                               v->mhits[v->nmhit].w = mw; v->mhits[v->nmhit].h = mh; v->mhits[v->nmhit].m = m; v->nmhit++; } }
            else { set_font(c, 0); set_color(c, m->state == MED_FAILED ? CERR : CSTAT);
                   const char *ph = m->state == MED_FAILED ? "[image failed]" : "[loading image\xE2\x80\xA6]";
                   IupDrawText(c, ph, (int)strlen(ph), cont, my, text_w(c, ph, (int)strlen(ph)), lh);
                   m->rw = m->rh = 0; }
        }
        mediah += mh + 4;
    }
    return texth + mediah;
}

static int view_is_live(view_t *v) { return v == current && v->stick; }
static int view_divider_h(view_t *v) {
    return (v->unread && v->unread_at > 0 && v->unread_at < v->nit) ? v->line_h + 8 : 0;
}

static void draw_divider(Ihandle *c, int y, int W, int lh) {
    const char *lbl = "New messages";
    int midy = y + (lh + 8) / 2;
    int tw = text_w(c, lbl, (int)strlen(lbl)), tx = W - tw - 12;
    set_color(c, CDIV);
    if (tx - 6 > 8) IupDrawLine(c, 8, midy, tx - 6, midy);
    if (tx + tw + 6 < W - 8) IupDrawLine(c, tx + tw + 6, midy, W - 8, midy);
    set_font(c, 0);
    IupDrawText(c, lbl, (int)strlen(lbl), tx, y + 4, tw, lh);
}

static void relayout(view_t *v, Ihandle *c, int W) {
    set_font(c, 0);
    int w = 0, h = 0; IupDrawGetTextSize(c, "Ap", 2, &w, &h);
    v->line_h = h > 0 ? h : 14;
    v->indent = 0;

    v->nick_col = 0;
    int total = 0;
    for (int i = 0; i < v->nit; i++) { int hh = layout_item(v, c, i, W, 0, 0); v->item_h[i] = hh; total += hh; }
    v->total_h = total; v->lay_w = W;
}

static void view_measure_item(view_t *v, int idx) {
    if (v->lay_w <= 0 || !v->tab || idx < 0 || idx >= v->nit) return;
    int old = v->item_h[idx];
    int hh = layout_item(v, v->tab, idx, v->lay_w, 0, 0);
    v->item_h[idx] = hh;
    v->total_h += hh - old;
}

static int view_item_of_media(view_t *v, media_t *m) {
    for (int i = 0; i < v->nit; i++)
        for (int k = 0; k < v->items[i].nmedia; k++)
            if (v->items[i].media[k] == m) return i;
    return -1;
}

static int cb_canvas_action(Ihandle *c, float px, float py) {
    (void)px; (void)py;
    view_t *v = view_by_canvas(c); if (!v) return IUP_DEFAULT;
    if (!TH.p) ui_theme_init();
    IupDrawBegin(c);
    int W = 0, H = 0; IupDrawGetSize(c, &W, &H);
    v->cw = W; v->ch = H;
    IupDrawSetClipRect(c, 0, 0, W, H);
    set_color(c, CBG); IupSetAttribute(c, "DRAWSTYLE", "FILL"); IupDrawRectangle(c, 0, 0, W, H);
    if (W > 0 && v->lay_w != W) relayout(v, c, W);
    int dh = view_divider_h(v);
    int total = v->total_h + dh;
    int maxpos = total - H; if (maxpos < 0) maxpos = 0;
    if (v->pending_unread_scroll && v->lay_w == W && W > 0) {
        v->pending_unread_scroll = 0;
        int uy = 0; for (int i = 0; i < v->unread_at && i < v->nit; i++) uy += v->item_h[i];
        v->posy = uy; v->stick = 0;
    }
    if (v->seek_to && v->lay_w == W && W > 0) {
        int k = v->seek_to - 1; v->seek_to = 0;
        int sy = 0; for (int i = 0; i < k && i < v->nit; i++) sy += v->item_h[i];
        v->posy = sy; v->stick = 0;
    }
    if (v->stick) v->posy = maxpos;
    if (v->posy > maxpos) v->posy = maxpos;
    if (v->posy < 0) v->posy = 0;
    IupSetInt(c, "YMIN", 0); IupSetInt(c, "YMAX", total > 0 ? total : 1);
    IupSetInt(c, "DY", H); IupSetInt(c, "POSY", v->posy);
    v->nlinks = 0; v->nmhit = 0;
    int y = 0;
    for (int i = 0; i < v->nit; i++) {
        if (dh && i == v->unread_at) { draw_divider(c, y - v->posy, W, v->line_h); y += dh; }
        int hh = v->item_h[i];
        if (y + hh > v->posy && y < v->posy + H) layout_item(v, c, i, W, y - v->posy, 1);
        y += hh;
    }
    IupDrawEnd(c);

    if (v == current && v->posy >= maxpos && v->unread) { mark_read(v); IupUpdate(c); }
    return IUP_DEFAULT;
}
static int cb_canvas_scroll(Ihandle *c, int op, float px, float py) {
    (void)op; (void)px; (void)py;
    view_t *v = view_by_canvas(c); if (!v) return IUP_DEFAULT;
    v->posy = IupGetInt(c, "POSY");
    v->stick = (v->posy + v->ch >= v->total_h - 4);
    if (v->stick) mark_read(v);
    IupUpdate(c);
    return IUP_DEFAULT;
}
static int cb_canvas_wheel(Ihandle *c, float delta, int x, int y, char *st) {
    (void)x; (void)y; (void)st;
    view_t *v = view_by_canvas(c); if (!v) return IUP_DEFAULT;
    int step = v->line_h > 0 ? v->line_h * 3 : 48;
    v->posy -= (int)(delta * step);
    int maxpos = v->total_h - v->ch; if (maxpos < 0) maxpos = 0;
    if (v->posy > maxpos) v->posy = maxpos;
    if (v->posy < 0) v->posy = 0;
    v->stick = (v->posy + v->ch >= v->total_h - 4);
    if (v->stick) mark_read(v);
    IupUpdate(c);
    return IUP_DEFAULT;
}

static void canvas_hit(view_t *v, int mx, int my, int *item, int *off) {
    *item = 0; *off = 0;
    if (v->nit == 0 || !v->tab || v->cw <= 0) return;
    int cy = my + v->posy;
    int dh = view_divider_h(v);
    int y = 0, idx = -1;
    for (int i = 0; i < v->nit; i++) { if (dh && i == v->unread_at) y += dh;
                                       if (cy >= y && cy < y + v->item_h[i]) { idx = i; break; } y += v->item_h[i]; }
    if (idx < 0) { if (cy < 0) return; idx = v->nit - 1; y -= v->item_h[idx]; }
    *item = idx;
    g_hit_on = 1; g_hit_item = idx; g_hit_x = mx; g_hit_y = cy - y; g_hit_off = 0; g_hit_best = -1;

    layout_item(v, v->tab, idx, v->cw, 0, 0);
    g_hit_on = 0;
    *off = g_hit_off;
}

static int item_canon(view_t *v, int idx, char *out, size_t osz) {
    vitem_t *it = &v->items[idx];
    char ts[48], tsraw[24]; time_t tt = (time_t)it->ts; struct tm *lt = localtime(&tt);
    strftime(tsraw, sizeof tsraw, "[%H:%M] ", lt);
    snprintf(ts, sizeof ts, "%s%s", it->encrypted ? LOCK_GLYPH : "", tsraw);
    int n = snprintf(out, osz, "%s", ts);
    if (it->kind == VIT_MSG || it->kind == VIT_SELF) n += snprintf(out + n, osz - n, "%s: ", it->nick);
    if (body_is_pre(it->body)) {
        for (const char *p = it->body; *p && n < (int)osz - 1; p++) out[n++] = *p;
        out[n] = '\0';
        return n;
    }
    int first = 1;
    for (const char *p = it->body; *p && n < (int)osz - 1; ) {
        int hardbreak = 0;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') { if (*p == '\n') hardbreak = 1; p++; }
        if (!*p) break;
        const char *ws = p; while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        if (!first) out[n++] = hardbreak ? '\n' : ' ';
        int wlen = (int)(p - ws); if (wlen > (int)osz - 1 - n) wlen = (int)osz - 1 - n;
        memcpy(out + n, ws, wlen); n += wlen; first = 0;
    }
    out[n] = '\0';
    return n;
}
static void clip_set(const char *s) { Ihandle *cb = IupClipboard(); IupSetStrAttribute(cb, "TEXT", s); IupDestroy(cb); }

static char *build_selection(view_t *v) {
    if (!v->sel_on) return NULL;
    int si, so, ei, eo; sel_range(v, &si, &so, &ei, &eo);
    size_t cap = 4096; char *buf = malloc(cap); if (!buf) return NULL; size_t used = 0;
    for (int i = si; i <= ei && i < v->nit; i++) {
        char line[4096]; int len = item_canon(v, i, line, sizeof line);
        int lo = (i == si) ? so : 0, hi = (i == ei) ? eo : len;
        if (lo < 0) lo = 0; if (hi > len) hi = len; if (hi < lo) hi = lo;
        size_t need = used + (size_t)(hi - lo) + 2;
        if (need > cap) { cap = need * 2; char *nb = realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
        memcpy(buf + used, line + lo, (size_t)(hi - lo)); used += (size_t)(hi - lo);
        if (i < ei) buf[used++] = '\n';
    }
    buf[used] = '\0';
    return buf;
}
static void copy_selection(view_t *v) {
    char *s = build_selection(v); if (!s) return;
    clip_set(s); free(s);
}
static void sel_clear(view_t *v) { v->sel_on = 0; if (v->tab) IupUpdate(v->tab); }
static void sel_all(view_t *v) {
    if (v->nit == 0) return;
    v->a_item = 0; v->a_off = 0; v->c_item = v->nit - 1;
    char line[4096]; v->c_off = item_canon(v, v->nit - 1, line, sizeof line);
    v->sel_on = 1; if (v->tab) IupUpdate(v->tab);
}

static view_t *g_ctxview; static int g_ctxitem; static char g_ctxurl[512];
static int cxc_copy(Ihandle *ih)    { (void)ih; if (g_ctxview) copy_selection(g_ctxview); return IUP_DEFAULT; }
static int cxc_copymsg(Ihandle *ih) { (void)ih; if (g_ctxview && g_ctxitem >= 0 && g_ctxitem < g_ctxview->nit) {
        char line[4096]; item_canon(g_ctxview, g_ctxitem, line, sizeof line); clip_set(line); } return IUP_DEFAULT; }
static int cxc_save(Ihandle *ih)    { (void)ih;
    view_t *v = g_ctxview;
    if (!v || g_ctxitem < 0 || g_ctxitem >= v->nit) return IUP_DEFAULT;
    vitem_t *it = &v->items[g_ctxitem];
    if (tri_saved_add(core, v->acct, v->target, it->nick, it->body, it->ts) == 0)
        saved_view_add(v->acct, v->target, it->nick, it->body, it->ts);
    else IupMessage("Trichat - save", tri_last_error());
    return IUP_DEFAULT; }
static int cxc_selall(Ihandle *ih)  { (void)ih; if (g_ctxview) sel_all(g_ctxview); return IUP_DEFAULT; }
static int cxc_clear(Ihandle *ih)   { (void)ih; if (g_ctxview) sel_clear(g_ctxview); return IUP_DEFAULT; }
static int cxc_reply(Ihandle *ih)   { (void)ih;
    view_t *v = g_ctxview;
    if (!v || g_ctxitem < 0 || g_ctxitem >= v->nit) return IUP_DEFAULT;
    vitem_t *it = &v->items[g_ctxitem];
    reply_begin(it->nick[0] ? it->nick : key_name(v->target), it->body);
    if (input) IupSetFocus(input);
    return IUP_DEFAULT; }

static void reply_clear(void) {
    g_reply_nick[0] = g_reply_text[0] = '\0';
    if (replybar) { IupSetAttribute(replybar, "FLOATING", "YES"); IupSetAttribute(replybar, "VISIBLE", "NO");
                    if (dlg && IupGetAttribute(dlg, "WID")) IupRefresh(dlg); }
}
static void reply_begin(const char *nick, const char *body) {
    snprintf(g_reply_nick, sizeof g_reply_nick, "%s", nick ? nick : "");
    snprintf(g_reply_text, sizeof g_reply_text, "%s", body ? body : "");
    if (reply_preview) {
        char prev[120]; snprintf(prev, sizeof prev, "\xE2\x86\xA9 %s: %.60s%s", g_reply_nick, g_reply_text,
                                 strlen(g_reply_text) > 60 ? "\xE2\x80\xA6" : "");
        for (char *q = prev; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        IupSetStrAttribute(reply_preview, "TITLE", prev);
    }
    if (replybar) { IupSetAttribute(replybar, "FLOATING", "NO"); IupSetAttribute(replybar, "VISIBLE", "YES");
                    if (dlg && IupGetAttribute(dlg, "WID")) IupRefresh(dlg); }
}
static int cb_reply_cancel(Ihandle *ih) { (void)ih; reply_clear(); return IUP_DEFAULT; }
static int cxl_open(Ihandle *ih)    { (void)ih; if (g_ctxurl[0]) IupHelp(g_ctxurl); return IUP_DEFAULT; }
static int cxl_copy(Ihandle *ih)    { (void)ih; if (g_ctxurl[0]) clip_set(g_ctxurl); return IUP_DEFAULT; }

static const char *link_at(view_t *v, int x, int y) {
    for (int i = 0; i < v->nlinks; i++)
        if (x >= v->links[i].x && x < v->links[i].x + v->links[i].w &&
            y >= v->links[i].y && y < v->links[i].y + v->links[i].h) return v->links[i].url;
    return NULL;
}
static void chat_context_menu(view_t *v, int x, int y) {
    g_ctxview = v; g_ctxurl[0] = '\0';
    int off; canvas_hit(v, x, y, &g_ctxitem, &off);
    const char *url = link_at(v, x, y);
    Ihandle *menu;
    if (url) {
        snprintf(g_ctxurl, sizeof g_ctxurl, "%s", url);
        menu = IupMenu(mk("Open link", (Icallback)cxl_open), mk("Copy link", (Icallback)cxl_copy), NULL);
    } else {
        menu = IupMenu(mk("Copy", (Icallback)cxc_copy), mk("Copy message", (Icallback)cxc_copymsg),
                       IupSeparator(), mk("Select all", (Icallback)cxc_selall), mk("Clear selection", (Icallback)cxc_clear), NULL);
        if (v->acct[0] != '*' && v->target[0] && g_ctxitem >= 0 && g_ctxitem < v->nit
            && (v->items[g_ctxitem].kind == VIT_MSG || v->items[g_ctxitem].kind == VIT_SELF))
            { IupAppend(menu, IupSeparator());
              IupAppend(menu, mk("Reply", (Icallback)cxc_reply));
              IupAppend(menu, mk("Save message", (Icallback)cxc_save)); }
    }
    IupPopup(menu, IUP_MOUSEPOS, IUP_MOUSEPOS);
    IupDestroy(menu);
}

static int cb_canvas_motion(Ihandle *c, int x, int y, char *st) {
    (void)st;
    view_t *v = view_by_canvas(c); if (!v || !v->dragging) return IUP_DEFAULT;
    canvas_hit(v, x, y, &v->c_item, &v->c_off);
    v->sel_on = !(v->a_item == v->c_item && v->a_off == v->c_off);
    IupUpdate(c);
    return IUP_DEFAULT;
}
static int cb_canvas_button(Ihandle *c, int but, int pressed, int x, int y, char *st) {
    (void)st;
    view_t *v = view_by_canvas(c); if (!v) return IUP_DEFAULT;
    if (but == IUP_BUTTON3 && pressed) {
        media_t *m = media_at(v, x, y);
        if (m) { g_ctxmedia = m; media_context_menu(); }
        else chat_context_menu(v, x, y);
        return IUP_DEFAULT;
    }
    if (but != IUP_BUTTON1) return IUP_DEFAULT;

    if (pressed && !strcmp(v->acct, "*:alert")) {
        int it, off; canvas_hit(v, x, y, &it, &off);
        const char *ak, *tg, *nk, *tx; long long ts;
        if (it >= 0 && tri_inbox_get(core, it, &ak, &tg, &nk, &tx, &ts)) {
            view_t *sv = view_find(ak, tg);
            if (sv) switch_to(sv);
        }
        return IUP_DEFAULT;
    }

    if (pressed && !strcmp(v->acct, SAVED_KEY)) {
        int it, off; canvas_hit(v, x, y, &it, &off);
        const char *ak, *tg, *nk, *tx; long long ts;
        if (it >= 0 && tri_saved_get(core, it, &ak, &tg, &nk, &tx, &ts)) {
            view_t *sv = view_find(ak, tg);
            if (sv) switch_to(sv);
        }
        return IUP_DEFAULT;
    }
    if (pressed) {
        v->dragging = 1; v->press_x = x; v->press_y = y;
        canvas_hit(v, x, y, &v->a_item, &v->a_off);
        v->c_item = v->a_item; v->c_off = v->a_off;
        return IUP_DEFAULT;
    }

    v->dragging = 0;
    int moved = (x - v->press_x) * (x - v->press_x) + (y - v->press_y) * (y - v->press_y) > 9;
    if (moved && v->sel_on) { IupUpdate(c); return IUP_DEFAULT; }

    if (v->sel_on) { v->sel_on = 0; IupUpdate(c); }
    media_t *m = media_at(v, x, y);
    if (m) { media_open(m); return IUP_DEFAULT; }
    const char *url = link_at(v, x, y);
    if (url) IupHelp(url);
    return IUP_DEFAULT;
}
static int cb_canvas_resize(Ihandle *c, int w, int h) {
    (void)w; (void)h;
    view_t *v = view_by_canvas(c); if (v) v->lay_w = -1;
    IupUpdate(c);
    return IUP_DEFAULT;
}
static int cb_canvas_copy(Ihandle *c) {
    view_t *v = view_by_canvas(c); if (v && v->sel_on) copy_selection(v);
    return IUP_DEFAULT;
}

static int mentions_nick(const char *body, const char *nick) {
    size_t nl = strlen(nick);
    if (nl < 2) return 0;
    for (const char *p = body; *p; p++) {
        if (strncasecmp(p, nick, nl)) continue;
        int lok = (p == body) || !isalnum((unsigned char)p[-1]);
        int rok = !isalnum((unsigned char)p[nl]);
        if (lok && rok) return 1;
    }
    return 0;
}

static void view_add_enc(view_t *v, int kind, const char *nick, const char *body, long long ts, int encrypted) {
    if (v->nit >= VIT_CAP) { media_detach(&v->items[0]); free(v->items[0].body);
                             if (v->lay_w > 0) { v->total_h -= v->item_h[0];
                                                 memmove(v->item_h, v->item_h + 1, (VIT_CAP - 1) * sizeof(int)); }
                             memmove(v->items, v->items + 1, (VIT_CAP - 1) * sizeof(vitem_t)); v->nit--;
                             if (v->unread_at > 0) v->unread_at--;
                             if (v->sel_on) v->sel_on = 0;     }
    vitem_t *it = &v->items[v->nit++];
    it->ts = ts ? ts : (long long)time(NULL);
    it->kind = kind;
    snprintf(it->nick, sizeof it->nick, "%s", nick ? nick : "");
    it->body = strdup(body ? body : "");
    it->nmedia = 0;
    it->highlight = 0;
    it->encrypted = (unsigned char)(encrypted ? 1 : 0);

    if (opt_embed && (kind == VIT_MSG || kind == VIT_SELF)) scan_media(v, it);
    if (kind == VIT_MSG) it->highlight = mentions_nick(it->body, key_name(v->acct));

    if (view_is_live(v)) v->unread_at = v->nit;
    if (v->lay_w > 0 && v->tab) { v->item_h[v->nit - 1] = 0; view_measure_item(v, v->nit - 1); }
    else v->lay_w = -1;
    if (v->tab) IupUpdate(v->tab);
}
static void view_add(view_t *v, int kind, const char *nick, const char *body, long long ts) {
    view_add_enc(v, kind, nick, body, ts, 0);
}

static int view_has_hist_dup(view_t *v, const char *nick, const char *body) {
    const char *n = nick ? nick : "", *b = body ? body : "";
    for (int i = v->nit - 1; i >= 0; i--) {
        vitem_t *it = &v->items[i];
        if ((it->kind == VIT_MSG || it->kind == VIT_SELF) && !strcmp(it->nick, n) && it->body && !strcmp(it->body, b))
            return 1;
    }
    return 0;
}

static void view_refresh_members(void) {
    if (!members) return;
    IupSetAttribute(members, "REMOVEITEM", "ALL");
    if (!current || !current->target[0]) return;
    for (int i = 0; i < tri_roster_count(core); i++) {
        const char *ak = NULL, *ch = NULL, *us = NULL; int tk = 0; tri_roster_get(core, i, &ak, &ch, &us, &tk);
        if (strcmp(ak, current->acct) || strcmp(ch, current->target)) continue;
        const char *dot = (tk & TRI_VOICE_TALKING) ? "\xE2\x97\x8F " : "";
        const char *st  = (tk & TRI_VOICE_DEAF) ? "[deaf] " : (tk & TRI_VOICE_MUTED) ? "[muted] " : "";
        char lbl[176]; snprintf(lbl, sizeof lbl, "%s%s%s", dot, st, us);
        IupSetStrAttribute(members, "APPENDITEM", lbl);
    }
}

static const char *sniff_image(const unsigned char *d, size_t n) {
    if (n >= 8 && d[0] == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G') return "png";
    if (n >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) return "jpg";
    if (n >= 6 && (!memcmp(d, "GIF87a", 6) || !memcmp(d, "GIF89a", 6))) return "gif";
    if (n >= 12 && !memcmp(d, "RIFF", 4) && !memcmp(d + 8, "WEBP", 4)) return "webp";
    if (n >= 2 && d[0] == 'B' && d[1] == 'M') return "bmp";
    return NULL;
}
static void url_hash(const char *s, char *out, size_t osz) {
    unsigned long h = 5381; for (const char *p = s; *p; p++) h = h * 33 + (unsigned char)*p;
    snprintf(out, osz, "%08lx", h & 0xffffffffUL);
}
static unsigned char *b64decode(const char *s, const char *end, size_t *outlen) {
    unsigned char *o = malloc((size_t)(end - s) / 4 * 3 + 4); if (!o) return NULL;
    size_t n = 0; int q[4], qi = 0;
    for (const char *p = s; p < end && *p != '='; p++) {
        int v = tri_b64val((unsigned char)*p); if (v < 0) continue;
        q[qi++] = v;
        if (qi == 4) { o[n++] = (q[0] << 2) | (q[1] >> 4); o[n++] = (q[1] << 4) | (q[2] >> 2); o[n++] = (q[2] << 6) | q[3]; qi = 0; }
    }
    if (qi >= 2) { o[n++] = (q[0] << 2) | (q[1] >> 4); if (qi >= 3) o[n++] = (q[1] << 4) | (q[2] >> 2); }
    *outlen = n; return o;
}

static int img_decode_rgba(const char *path, unsigned char **out, int *ow, int *oh) {
    GError *e = NULL;
    GdkPixbuf *pb = gdk_pixbuf_new_from_file(path, &e);
    if (!pb) { if (e) g_error_free(e); return -1; }
    int w0 = gdk_pixbuf_get_width(pb), h0 = gdk_pixbuf_get_height(pb), tw = w0, th = h0;
    const int MAXW = 360, MAXH = 300;
    if (tw > MAXW) { th = th * MAXW / (tw ? tw : 1); tw = MAXW; }
    if (th > MAXH) { tw = tw * MAXH / (th ? th : 1); th = MAXH; }
    if (tw < 1) tw = 1; if (th < 1) th = 1;
    GdkPixbuf *sc = (tw != w0 || th != h0) ? gdk_pixbuf_scale_simple(pb, tw, th, GDK_INTERP_BILINEAR) : g_object_ref(pb);
    g_object_unref(pb);
    if (!sc) return -1;
    GdkPixbuf *rgba = gdk_pixbuf_get_has_alpha(sc) ? g_object_ref(sc) : gdk_pixbuf_add_alpha(sc, FALSE, 0, 0, 0);
    g_object_unref(sc);
    if (!rgba) return -1;
    int rs = gdk_pixbuf_get_rowstride(rgba);
    const guchar *px = gdk_pixbuf_get_pixels(rgba);
    unsigned char *buf = malloc((size_t)tw * th * 4);
    if (!buf) { g_object_unref(rgba); return -1; }
    for (int y = 0; y < th; y++) memcpy(buf + (size_t)y * tw * 4, px + (size_t)y * rs, (size_t)tw * 4);
    g_object_unref(rgba);
    *out = buf; *ow = tw; *oh = th;
    return 0;
}

static int thumb_from_rgba(media_t *m, unsigned char *buf, int tw, int th) {
    static int imc = 0; snprintf(m->imgname, sizeof m->imgname, "trimg%d", ++imc);
    Ihandle *img = IupImageRGBA(tw, th, buf);
    if (!img) { free(buf); m->imgname[0] = '\0'; return -1; }
    IupSetHandle(m->imgname, img);
    m->img = img; m->pixels = buf; m->w = tw; m->h = th;
    return 0;
}

static int load_thumb(media_t *m) {
    unsigned char *buf; int tw, th;
    if (img_decode_rgba(m->path, &buf, &tw, &th) != 0) return -1;
    return thumb_from_rgba(m, buf, tw, th);
}

static int load_theme_icon(const char *icon, int size, const char *name) {
    GtkIconTheme *th = gtk_icon_theme_get_default();
    GdkPixbuf *pb = th ? gtk_icon_theme_load_icon(th, icon, size, 0, NULL) : NULL;
    if (!pb) return -1;
    GdkPixbuf *rgba = gdk_pixbuf_get_has_alpha(pb) ? g_object_ref(pb) : gdk_pixbuf_add_alpha(pb, FALSE, 0, 0, 0);
    g_object_unref(pb);
    if (!rgba) return -1;
    int w = gdk_pixbuf_get_width(rgba), h = gdk_pixbuf_get_height(rgba), rs = gdk_pixbuf_get_rowstride(rgba);
    const guchar *px = gdk_pixbuf_get_pixels(rgba);
    unsigned char *buf = malloc((size_t)w * h * 4);
    if (!buf) { g_object_unref(rgba); return -1; }
    for (int y = 0; y < h; y++) memcpy(buf + (size_t)y * w * 4, px + (size_t)y * rs, (size_t)w * 4);
    g_object_unref(rgba);
    Ihandle *img = IupImageRGBA(w, h, buf);
    if (!img) { free(buf); return -1; }
    IupSetHandle(name, img);
    return 0;
}

static void geom_dump(void) {
    if (!getenv("TRICHAT_GEOM")) return;
    while (gtk_events_pending()) gtk_main_iteration();
    GtkWidget *root = dlg ? (GtkWidget *)IupGetAttribute(dlg, "WID") : NULL;
    if (!root || !GTK_IS_WIDGET(root)) return;

    Ihandle *shown = (Ihandle *)IupGetAttribute(tabs, "VALUE_HANDLE");
    if (!shown && current) shown = current->tab;
    struct { const char *n; Ihandle *h; } probe[] = {
        {"tabs", tabs}, {"canvas", shown},
        {"members", members}, {"attach", attach}, {"input", input},
    };
    int canvas_bottom = -1, tabs_right = -1, input_top = 999999, members_left = 999999;
    fprintf(stderr, "--- GEOM ---\n");
    for (unsigned i = 0; i < sizeof probe / sizeof *probe; i++) {
        GtkWidget *w = probe[i].h ? (GtkWidget *)IupGetAttribute(probe[i].h, "WID") : NULL;
        if (!w || !GTK_IS_WIDGET(w)) { fprintf(stderr, "GEOM %-8s (no widget)\n", probe[i].n); continue; }
        GtkAllocation al; gtk_widget_get_allocation(w, &al);
        int wx = 0, wy = 0; gtk_widget_translate_coordinates(w, root, 0, 0, &wx, &wy);
        fprintf(stderr, "GEOM %-8s left=%d right=%d  top=%d bottom=%d  (w=%d h=%d)\n",
                probe[i].n, wx, wx + al.width, wy, wy + al.height, al.width, al.height);
        if (!strcmp(probe[i].n, "canvas"))  canvas_bottom = wy + al.height;
        if (!strcmp(probe[i].n, "tabs"))    tabs_right = wx + al.width;
        if (!strcmp(probe[i].n, "input"))   input_top = wy;
        if (!strcmp(probe[i].n, "members")) members_left = wx;
    }
    int vov = canvas_bottom - input_top, hov = tabs_right - members_left;
    fprintf(stderr, "VERDICT: canvas-vs-input %s (%+dpx)   tabs-vs-members %s (%+dpx)\n",
            vov > 0 ? "OVERLAP" : "clean", vov, hov > 0 ? "OVERLAP" : "clean", hov);
}
static int cb_geom_timer(Ihandle *t) { (void)t; geom_dump(); return IUP_DEFAULT; }

static void media_free(media_t *m) {
    for (media_t **pp = &g_media; *pp; pp = &(*pp)->next) if (*pp == m) { *pp = m->next; break; }
    if (m->imgname[0]) IupSetHandle(m->imgname, NULL);
    if (m->img) IupDestroy(m->img);
    free(m->pixels); free(m);
}
static void media_detach(vitem_t *it) {
    for (int i = 0; i < it->nmedia; i++) {
        media_t *m = it->media[i];
        if (m->state == MED_PENDING) { m->orphan = 1; m->canvas = NULL; }
        else media_free(m);
    }
    it->nmedia = 0;
}

static void media_report(media_t *m, const char *reason) {
    char msg[400]; snprintf(msg, sizeof msg, "image failed (%s): %.200s", reason, m->url);
    view_t *v = view_by_canvas(m->canvas);
    if (v) { tri_event_t ev = { TRI_EV_ERROR, v->acct, v->target, msg, NULL, 0 }; on_event(NULL, &ev); }
    else tri_log(core, "%s", msg);
}

typedef struct imgjob {
    struct imgjob *next;
    media_t *token; unsigned uid;
    char path[600];
    unsigned char *buf; int tw, th, ok;
} imgjob;
static struct {
    pthread_t thread; int started;
    pthread_mutex_t lock; pthread_cond_t cond;
    int stop, wake_r, wake_w;
    imgjob *in_head, *in_tail, *out_head, *out_tail;
} g_imgdec = { .wake_r = -1, .wake_w = -1 };

static void *imgdec_worker(void *ud) {
    (void)ud;
    for (;;) {
        pthread_mutex_lock(&g_imgdec.lock);
        while (!g_imgdec.in_head && !g_imgdec.stop) pthread_cond_wait(&g_imgdec.cond, &g_imgdec.lock);
        if (!g_imgdec.in_head && g_imgdec.stop) { pthread_mutex_unlock(&g_imgdec.lock); break; }
        imgjob *j = g_imgdec.in_head; g_imgdec.in_head = j->next; if (!g_imgdec.in_head) g_imgdec.in_tail = NULL;
        pthread_mutex_unlock(&g_imgdec.lock);
        j->next = NULL;
        j->ok = (img_decode_rgba(j->path, &j->buf, &j->tw, &j->th) == 0);
        pthread_mutex_lock(&g_imgdec.lock);
        if (g_imgdec.out_tail) g_imgdec.out_tail->next = j; else g_imgdec.out_head = j;
        g_imgdec.out_tail = j;
        pthread_mutex_unlock(&g_imgdec.lock);
        char b = 1; ssize_t wr = write(g_imgdec.wake_w, &b, 1); (void)wr;
    }
    return NULL;
}

static void imgdec_complete(imgjob *j) {
    media_t *m = NULL;
    for (media_t *p = g_media; p; p = p->next) if (p == j->token && p->uid == j->uid) { m = p; break; }
    if (!m) { free(j->buf); return; }
    if (m->orphan) { free(j->buf); media_free(m); return; }
    if (j->ok && j->buf && thumb_from_rgba(m, j->buf, j->tw, j->th) == 0) m->state = MED_LOADED;
    else { if (!(j->ok && j->buf)) free(j->buf); m->state = MED_FAILED;
           media_report(m, "could not decode - unsupported image format?"); }
    view_t *v = view_by_canvas(m->canvas);
    if (v && v->tab) { view_measure_item(v, view_item_of_media(v, m)); IupUpdate(v->tab); }
}
static void imgdec_readable(void *ud, int fd) {
    (void)ud; (void)fd;
    char sink[64]; while (read(g_imgdec.wake_r, sink, sizeof sink) > 0) { }
    for (;;) {
        pthread_mutex_lock(&g_imgdec.lock);
        imgjob *j = g_imgdec.out_head;
        if (j) { g_imgdec.out_head = j->next; if (!g_imgdec.out_head) g_imgdec.out_tail = NULL; }
        pthread_mutex_unlock(&g_imgdec.lock);
        if (!j) break;
        imgdec_complete(j); free(j);
    }
}

static int imgdec_start(void) {
    if (g_imgdec.started) return 1;
    int fds[2]; if (pipe(fds) != 0) return 0;
    g_imgdec.wake_r = fds[0]; g_imgdec.wake_w = fds[1];
    int fl;
    if ((fl = fcntl(g_imgdec.wake_r, F_GETFL, 0)) >= 0) fcntl(g_imgdec.wake_r, F_SETFL, fl | O_NONBLOCK);
    if ((fl = fcntl(g_imgdec.wake_w, F_GETFL, 0)) >= 0) fcntl(g_imgdec.wake_w, F_SETFL, fl | O_NONBLOCK);
    if (pthread_mutex_init(&g_imgdec.lock, NULL) != 0) goto fail;
    if (pthread_cond_init(&g_imgdec.cond, NULL) != 0) { pthread_mutex_destroy(&g_imgdec.lock); goto fail; }
    if (pthread_create(&g_imgdec.thread, NULL, imgdec_worker, NULL) != 0) {
        pthread_cond_destroy(&g_imgdec.cond); pthread_mutex_destroy(&g_imgdec.lock); goto fail;
    }
    g_imgdec.started = 1;
    tri_core_add_fd(core, g_imgdec.wake_r, imgdec_readable, NULL);
    return 1;
fail:
    close(g_imgdec.wake_r); close(g_imgdec.wake_w); g_imgdec.wake_r = g_imgdec.wake_w = -1; return 0;
}

static int imgdec_submit(media_t *m) {
    if (!imgdec_start()) return 0;
    imgjob *j = calloc(1, sizeof *j); if (!j) return 0;
    j->token = m; j->uid = m->uid; snprintf(j->path, sizeof j->path, "%s", m->path);
    pthread_mutex_lock(&g_imgdec.lock);
    if (g_imgdec.in_tail) g_imgdec.in_tail->next = j; else g_imgdec.in_head = j;
    g_imgdec.in_tail = j;
    pthread_cond_signal(&g_imgdec.cond);
    pthread_mutex_unlock(&g_imgdec.lock);
    return 1;
}

static void finish_media(media_t *m, int ok) {
    if (m->orphan) { media_free(m); return; }
    if (ok) {
        if (imgdec_submit(m)) return;
        ok = (load_thumb(m) == 0);
        if (!ok) media_report(m, "could not decode - unsupported image format?");
        m->state = ok ? MED_LOADED : MED_FAILED;
    } else {
        m->state = MED_FAILED;
    }
    view_t *v = view_by_canvas(m->canvas);
    if (v && v->tab) { view_measure_item(v, view_item_of_media(v, m)); IupUpdate(v->tab); }
}
static void on_media_fetched(void *ud, int ok, int status, const char *body, size_t len, const char *ctype) {
    (void)ctype;
    media_t *m = ud;
    if (ok && status == 200 && len > 0 && sniff_image((const unsigned char *)body, len)) {
        FILE *f = fopen(m->path, "wb");
        if (f) { size_t wr = fwrite(body, 1, len, f); fclose(f); if (wr == len) { finish_media(m, 1); return; } }
        media_report(m, "could not write cache file");
    } else {
        char reason[220];
        if (!ok)                                        snprintf(reason, sizeof reason, "network/TLS: %s", tri_last_error());
        else if (status != 200)                         snprintf(reason, sizeof reason, "HTTP %d", status);
        else if (len == 0)                              snprintf(reason, sizeof reason, "empty response");
        else                                            snprintf(reason, sizeof reason, "not a recognized image (bad magic bytes)");
        media_report(m, reason);
    }
    finish_media(m, 0);
}

static media_t *media_new(view_t *v, const char *url) {
    static unsigned g_media_uid;
    media_t *m = calloc(1, sizeof *m); if (!m) return NULL;
    m->canvas = v->tab; m->state = MED_PENDING; m->uid = ++g_media_uid;
    snprintf(m->url, sizeof m->url, "%s", url);
    char h[16]; url_hash(url, h, sizeof h);
    snprintf(m->path, sizeof m->path, "%s/%s.img", g_mediadir, h);
    m->next = g_media; g_media = m;
    return m;
}
static int is_img_ext(const char *u, size_t len) {
    char t[1024]; if (len >= sizeof t) return 0;
    memcpy(t, u, len); t[len] = '\0';
    char *q = strpbrk(t, "?#"); if (q) *q = '\0';
    size_t L = strlen(t);
    static const char *const ext[] = { ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp" };
    for (int i = 0; i < 6; i++) { size_t el = strlen(ext[i]); if (L >= el && !strcasecmp(t + L - el, ext[i])) return 1; }
    return 0;
}

static void scan_media(view_t *v, vitem_t *it) {
    if (!g_mediadir[0]) return;
    char *nb = malloc(strlen(it->body) + 1); if (!nb) return;
    size_t no = 0; int wrote = 0, hadnl = 0;
    for (const char *b = it->body; *b; ) {
        while (*b == ' ' || *b == '\t' || *b == '\n') { if (*b == '\n') hadnl = 1; b++; }
        if (!*b) break;
        const char *ws = b; while (*b && *b != ' ' && *b != '\t' && *b != '\n') b++;
        size_t len = (size_t)(b - ws);
        int is_image = 0;
        if (it->nmedia < VIT_MEDIA && len > 11 && !strncmp(ws, "data:image/", 11)) {
            const char *c = ws; const char *comma = NULL;
            for (const char *q = ws; q < b - 6; q++) if (!strncmp(q, "base64,", 7)) { comma = q + 7; break; }
            (void)c;
            if (comma) {
                size_t dlen = 0; unsigned char *data = b64decode(comma, b, &dlen);
                if (data) {
                    if (dlen > 0 && sniff_image(data, dlen)) {
                        media_t *m = media_new(v, ws);
                        if (m) { FILE *f = fopen(m->path, "wb");
                                 if (f) { fwrite(data, 1, dlen, f); fclose(f); finish_media(m, 1); }
                                 else { media_free(m); m = NULL; }
                                 if (m) it->media[it->nmedia++] = m; }
                    }
                    free(data);
                }
                is_image = 1;
            }
        } else if (it->nmedia < VIT_MEDIA && ((len > 7 && !strncmp(ws, "http://", 7)) || (len > 8 && !strncmp(ws, "https://", 8))) && is_img_ext(ws, len)) {
            char url[1024]; memcpy(url, ws, len); url[len] = '\0';
            media_t *m = media_new(v, url);
            if (m) {
                it->media[it->nmedia++] = m;
                FILE *cf = fopen(m->path, "rb");
                if (cf) { fclose(cf); finish_media(m, 1); }
                else if (tri_http_get(core, url, on_media_fetched, m) != 0) m->state = MED_FAILED;
                is_image = 1;
            }
        }
        if (!is_image) {
            if (wrote && no < strlen(it->body)) nb[no++] = hadnl ? '\n' : ' ';
            memcpy(nb + no, ws, len); no += len; wrote = 1; hadnl = 0;
        }
    }
    nb[no] = '\0';
    free(it->body); it->body = nb;
}

static media_t *media_at(view_t *v, int x, int y) {
    for (int i = 0; i < v->nmhit; i++)
        if (x >= v->mhits[i].x && x < v->mhits[i].x + v->mhits[i].w &&
            y >= v->mhits[i].y && y < v->mhits[i].y + v->mhits[i].h) return v->mhits[i].m;
    return NULL;
}

static void media_open(media_t *m) {
    unsigned char magic[16]; size_t got = 0;
    FILE *f = fopen(m->path, "rb");
    if (!f) { if (strncmp(m->url, "data:", 5)) IupHelp(m->url); return; }
    got = fread(magic, 1, sizeof magic, f); fclose(f);
    const char *ext = sniff_image(magic, got);
    char opath[700]; snprintf(opath, sizeof opath, "%s", m->path);
    if (ext) {
        snprintf(opath, sizeof opath, "%s.%s", m->path, ext);
        FILE *in = fopen(m->path, "rb"), *out = fopen(opath, "wb");
        if (in && out) { char b[8192]; size_t r; while ((r = fread(b, 1, sizeof b, in)) > 0) fwrite(b, 1, r, out); }
        if (in) fclose(in); if (out) fclose(out);
    }
    if (IupExecute("xdg-open", opath) <= 0) { char u[720]; snprintf(u, sizeof u, "file://%s", opath); IupHelp(u); }
}

static int cxm_open(Ihandle *ih)   { (void)ih; if (g_ctxmedia) media_open(g_ctxmedia); return IUP_DEFAULT; }
static int cxm_copyurl(Ihandle *ih){ (void)ih; if (g_ctxmedia && strncmp(g_ctxmedia->url, "data:", 5)) {
        Ihandle *clip = IupClipboard(); IupSetStrAttribute(clip, "TEXT", g_ctxmedia->url); IupDestroy(clip); } return IUP_DEFAULT; }
static int cxm_saveas(Ihandle *ih) {
    (void)ih; if (!g_ctxmedia) return IUP_DEFAULT;
    Ihandle *fd = IupFileDlg();
    IupSetAttribute(fd, "DIALOGTYPE", "SAVE"); IupSetAttribute(fd, "TITLE", "Save image as");
    IupPopup(fd, IUP_CENTER, IUP_CENTER);
    if (IupGetInt(fd, "STATUS") >= 0) {
        const char *dest = IupGetAttribute(fd, "VALUE");
        FILE *in = fopen(g_ctxmedia->path, "rb"), *out = dest ? fopen(dest, "wb") : NULL;
        if (in && out) { char b[8192]; size_t r; while ((r = fread(b, 1, sizeof b, in)) > 0) fwrite(b, 1, r, out); }
        else IupMessage("Trichat", "Could not save the image.");
        if (in) fclose(in); if (out) fclose(out);
    }
    IupDestroy(fd);
    return IUP_DEFAULT;
}
static int cxm_reload(Ihandle *ih) {
    (void)ih; media_t *m = g_ctxmedia; if (!m) return IUP_DEFAULT;
    int is_http = !strncmp(m->url, "http", 4);
    if (is_http) unlink(m->path);
    if (m->imgname[0]) { IupSetHandle(m->imgname, NULL); if (m->img) IupDestroy(m->img); m->img = NULL; m->imgname[0] = '\0'; }
    free(m->pixels); m->pixels = NULL; m->state = MED_PENDING;
    view_t *v = view_by_canvas(m->canvas); if (v && v->tab) { view_measure_item(v, view_item_of_media(v, m)); IupUpdate(v->tab); }
    if (is_http) { if (tri_http_get(core, m->url, on_media_fetched, m) != 0) finish_media(m, 0); }
    else finish_media(m, 1);
    return IUP_DEFAULT;
}
static void media_context_menu(void) {
    Ihandle *menu = IupMenu(mk("Open full size", (Icallback)cxm_open),
                            mk("Copy image URL", (Icallback)cxm_copyurl),
                            mk("Save image as\xE2\x80\xA6", (Icallback)cxm_saveas),
                            IupSeparator(),
                            mk("Reload", (Icallback)cxm_reload), NULL);
    IupPopup(menu, IUP_MOUSEPOS, IUP_MOUSEPOS);
    IupDestroy(menu);
}

static void media_dir_init(void) {
    const char *base = getenv("XDG_CACHE_HOME"); char root[400];
    if (base && base[0]) snprintf(root, sizeof root, "%s/trichat", base);
    else { const char *home = getenv("HOME"); snprintf(root, sizeof root, "%s/.cache/trichat", home ? home : "/tmp"); }
    mkdir(root, 0700);
    snprintf(g_mediadir, sizeof g_mediadir, "%s/media", root);
    mkdir(g_mediadir, 0700);
}
static void media_purge(void) {
    if (!g_mediadir[0]) return;
    DIR *d = opendir(g_mediadir); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char p[640]; snprintf(p, sizeof p, "%s/%s", g_mediadir, e->d_name); unlink(p);
    }
    closedir(d);
}

static int tree_add(int parentNode, int prevSibling, int branch, const char *label) {
    char ref[48];
    if (prevSibling < 0) snprintf(ref, sizeof ref, "%s%d", branch ? "ADDBRANCH" : "ADDLEAF", parentNode);
    else                 snprintf(ref, sizeof ref, "%s%d", branch ? "INSERTBRANCH" : "INSERTLEAF", prevSibling);
    IupSetStrAttribute(tree, ref, label);
    return IupGetInt(tree, "LASTADDNODE");
}

static int add_channel_node(view_t *v, const char *key, int acctNode, int prev) {
    char label[320]; int n = snprintf(label, sizeof label, "%s", v->target);
    int fc = tri_folder_ref_count_for(key, v->target);
    for (int k = 0; k < fc && n < (int)sizeof label; k++) {
        const char *fn = tri_folder_ref_name_for(key, v->target, k);
        n += snprintf(label + n, sizeof label - n, "%s%s", k == 0 ? "  (also in " : ", ", fn ? fn : "?");
    }
    if (fc > 0 && n < (int)sizeof label) snprintf(label + n, sizeof label - n, ")");
    int node = tree_add(acctNode, prev, 0, label);
    nodemap_add(node, NODE_CHANNEL, acctNode, 0, v, NULL, NULL, key, v->target);
    return node;
}

static int chan_occupancy(const char *acctkey, const char *name) {
    int n = 0;
    for (int i = 0; i < tri_roster_count(core); i++) {
        const char *ak = NULL, *ch = NULL, *us = NULL; int tk = 0; tri_roster_get(core, i, &ak, &ch, &us, &tk);
        if (!strcmp(ak, acctkey) && !strcmp(ch, name)) n++;
    }
    return n;
}
static void mumble_chan_label(const char *acctkey, const char *name, char *out, size_t sz) {
    int occ = chan_occupancy(acctkey, name);
    if (occ > 0) snprintf(out, sz, "%s (%d)", name, occ);
    else         snprintf(out, sz, "%s", name);
}
static int chantree_has(const char *acctkey, const char *name) {
    for (int i = 0; i < tri_chantree_count(core); i++) {
        const char *ak, *nm; unsigned id, par; tri_chantree_get(core, i, &ak, &id, &par, &nm);
        if (!strcmp(ak, acctkey) && !strcmp(nm, name)) return 1;
    }
    return 0;
}
static int chantree_is_root(const char *acctkey, unsigned id, unsigned parent) {
    if (parent == id) return 1;
    for (int i = 0; i < tri_chantree_count(core); i++) {
        const char *ak, *nm; unsigned cid, cpar; tri_chantree_get(core, i, &ak, &cid, &cpar, &nm);
        if (!strcmp(ak, acctkey) && cid == parent) return 0;
    }
    return 1;
}
static int add_mumble_chan(const char *acctkey, unsigned id, const char *name, int acctNode, int prev, int depth) {
    int has_child = 0;
    if (depth < 32) for (int i = 0; i < tri_chantree_count(core); i++) {
        const char *ak, *nm; unsigned cid, cpar; tri_chantree_get(core, i, &ak, &cid, &cpar, &nm);
        if (!strcmp(ak, acctkey) && cpar == id && cid != id) { has_child = 1; break; }
    }
    char label[192]; mumble_chan_label(acctkey, name, label, sizeof label);
    int node = tree_add(acctNode, prev, has_child ? 1 : 0, label);
    nodemap_add(node, NODE_CHANNEL, acctNode, has_child ? 1 : 0, view_find(acctkey, name), NULL, NULL, acctkey, name);
    if (has_child && depth < 32) {
        int cprev = -1;
        for (int i = 0; i < tri_chantree_count(core); i++) {
            const char *ak = NULL, *nm = NULL; unsigned cid = 0, cpar = 0; tri_chantree_get(core, i, &ak, &cid, &cpar, &nm);
            if (strcmp(ak, acctkey) || cpar != id || cid == id) continue;
            cprev = add_mumble_chan(acctkey, cid, nm, node, cprev, depth + 1);
        }
    }
    return node;
}

static void refresh_channel_occupancy(void) {
    for (int i = 0; i < nnodemap; i++) {
        if (nodemap[i].kind != NODE_CHANNEL || !nodemap[i].acctkey[0]) continue;
        if (!chantree_has(nodemap[i].acctkey, nodemap[i].target)) continue;
        char label[192]; mumble_chan_label(nodemap[i].acctkey, nodemap[i].target, label, sizeof label);
        IupSetStrAttributeId(tree, "TITLE", nodemap[i].node, label);
    }
}

static int add_account_node(account_t *a, int parentNode, int prev, int kind) {
    const char *key = tri_account_key(a);
    tri_conn_state cs = tri_account_state(a);
    const char *dot = cs == TRI_CS_ONLINE ? "\xE2\x97\x8F " : cs == TRI_CS_CONNECTING ? "\xE2\x97\x8C " : "\xE2\x97\x8B ";
    char buf[160]; snprintf(buf, sizeof buf, "%s%s: %s", dot, tri_account_backend(a), tri_account_name(a));
    int node = tree_add(parentNode, prev, 1, buf);
    nodemap_add(node, kind, parentNode, 1, NULL, a, NULL, key, NULL);
    int cprev = -1;
    int is_mumble = !strcmp(tri_account_backend(a), "mumble"), rendered_tree = 0;
    if (is_mumble) {
        for (int i = 0; i < tri_chantree_count(core); i++) {
            const char *ak = NULL, *nm = NULL; unsigned id = 0, par = 0; tri_chantree_get(core, i, &ak, &id, &par, &nm);
            if (strcmp(ak, key) || !chantree_is_root(key, id, par)) continue;
            cprev = add_mumble_chan(key, id, nm, node, cprev, 0); rendered_tree = 1;
        }
    }
    for (int i = 0; i < nviews; i++) {
        if (strcmp(views[i].acct, key) || !views[i].target[0]) continue;
        if (is_mumble && rendered_tree && chantree_has(key, views[i].target)) continue;
        cprev = add_channel_node(&views[i], key, node, cprev);
    }
    return node;
}

static int add_folder_node(tri_folder_t *f, int parentNode, int prev) {
    int node = tree_add(parentNode, prev, 1, tri_folder_name(f));
    nodemap_add(node, NODE_FOLDER, parentNode, 1, NULL, NULL, f, NULL, NULL);
    int cprev = -1, n = tri_folder_item_count(f);
    for (int i = 0; i < n; i++) {
        tri_folder_item_t it = tri_folder_item_get(f, i);
        if (it.kind == TRI_ITEM_ACCOUNT)
            cprev = add_account_node(it.account, node, cprev, NODE_FOLDERACCT);
        else if (it.kind == TRI_ITEM_FOLDER)
            cprev = add_folder_node(it.folder, node, cprev);
        else {
            char label[280]; snprintf(label, sizeof label, "%s (%s)", it.target, key_name(it.acctkey));
            int rn = tree_add(node, cprev, 0, label);
            nodemap_add(rn, NODE_FOLDERCHANREF, node, 0, view_find(it.acctkey, it.target), NULL, f, it.acctkey, it.target);
            cprev = rn;
        }
    }
    return node;
}

static void node_ident(int i, char *out, size_t n) {
    switch (nodemap[i].kind) {
        case NODE_ACCOUNT: case NODE_FOLDERACCT: snprintf(out, n, "A%p", (void *)nodemap[i].account); break;
        case NODE_FOLDER:                        snprintf(out, n, "F%p", (void *)nodemap[i].folder); break;
        case NODE_CHANNEL:                       snprintf(out, n, "C\x1f%s\x1f%s", nodemap[i].acctkey, nodemap[i].target); break;
        case NODE_FOLDERCHANREF:                 snprintf(out, n, "R%p\x1f%s\x1f%s", (void *)nodemap[i].folder, nodemap[i].acctkey, nodemap[i].target); break;
        case NODE_INBOX:                         snprintf(out, n, "I"); break;
        case NODE_SAVED:                         snprintf(out, n, "S"); break;
        default: out[0] = '\0';
    }
}

static char saved_collapsed[512][160];
static int  nsaved_collapsed;
static char saved_sel[160];
static int  expand_pending;
static void capture_tree_state(void) {
    saved_sel[0] = '\0';
    int si = nodemap_find(IupGetInt(tree, "VALUE"));
    if (si >= 0) node_ident(si, saved_sel, sizeof saved_sel);
    if (expand_pending) return;
    nsaved_collapsed = 0;
    for (int i = 0; i < nnodemap; i++) {
        if (!nodemap[i].branch) continue;
        const char *st = IupGetAttributeId(tree, "STATE", nodemap[i].node);
        if (st && !strcmp(st, "COLLAPSED") && nsaved_collapsed < 512)
            node_ident(i, saved_collapsed[nsaved_collapsed++], 160);
    }
}

static const char *tree_default_fg(void) {
    static char fg[16] = "";
    if (!fg[0]) { const char *v = tree ? IupGetAttribute(tree, "FGCOLOR") : NULL;
                  snprintf(fg, sizeof fg, "%s", v && v[0] ? v : "0 0 0"); }
    return fg;
}
static const char *unread_color(int unread) {
    return unread == 2 ? "220 90 90" : unread == 1 ? "110 150 235" : tree_default_fg();
}

static void color_view_nodes(view_t *v) {
    const char *col = unread_color(v->unread);
    for (int i = 0; i < nnodemap; i++)
        if (nodemap[i].v == v && (nodemap[i].kind == NODE_CHANNEL || nodemap[i].kind == NODE_FOLDERCHANREF || nodemap[i].kind == NODE_INBOX))
            IupSetAttributeId(tree, "COLOR", nodemap[i].node, col);
    IupSetAttribute(tree, "REDRAW", "YES");
}

static void mark_read(view_t *v) {
    if (!v) return;
    v->unread_at = v->nit;
    if (v->unread) { v->unread = 0; color_view_nodes(v); }
}

static void restore_tree_state(void) {
    for (int i = 0; i < nnodemap; i++) {
        int k = nodemap[i].kind;
        const char *img = k == NODE_FOLDER ? "TRI_IMG_FOLDER"
                        : (k == NODE_ACCOUNT || k == NODE_FOLDERACCT) ? "TRI_IMG_ACCT"
                        : (k == NODE_CHANNEL || k == NODE_FOLDERCHANREF) ? "TRI_IMG_CHAN"
                        : k == NODE_INBOX ? "TRI_IMG_INBOX"
                        : k == NODE_SAVED ? "TRI_IMG_SAVED" : NULL;
        if (img && IupGetHandle(img)) { IupSetAttributeId(tree, "IMAGE", nodemap[i].node, img); IupSetAttributeId(tree, "IMAGEEXPANDED", nodemap[i].node, img); }
        if ((nodemap[i].kind == NODE_CHANNEL || nodemap[i].kind == NODE_FOLDERCHANREF || nodemap[i].kind == NODE_INBOX) && nodemap[i].v)
            IupSetAttributeId(tree, "COLOR", nodemap[i].node, unread_color(nodemap[i].v->unread));
    }
    expand_pending = 1;
    if (saved_sel[0]) for (int i = 0; i < nnodemap; i++) {
        char id[160]; node_ident(i, id, sizeof id);
        if (id[0] && !strcmp(id, saved_sel)) { IupSetInt(tree, "VALUE", nodemap[i].node); break; }
    }
}

static void apply_tree_expansion(void) {
    if (!expand_pending) return;
    expand_pending = 0;
    IupSetAttribute(tree, "EXPANDALL", "YES");
    for (int i = 0; i < nnodemap; i++) {
        if (!nodemap[i].branch) continue;
        char id[160]; node_ident(i, id, sizeof id);
        for (int j = 0; j < nsaved_collapsed; j++)
            if (!strcmp(id, saved_collapsed[j])) { IupSetAttributeId(tree, "STATE", nodemap[i].node, "COLLAPSED"); break; }
    }
}

static void rebuild_tree(void) {
    capture_tree_state();
    IupSetAttribute(tree, "ADDEXPANDED", "NO");
    IupSetAttribute(tree, "DELNODE0", "CHILDREN");
    nnodemap = 0;
    int prev = -1;

    int inode = tree_add(0, prev, 0, "Inbox");
    nodemap_add(inode, NODE_INBOX, 0, 0, inbox_view(), NULL, NULL, INBOX_KEY, "");
    prev = inode;
    int snode = tree_add(0, prev, 0, "Saved");
    nodemap_add(snode, NODE_SAVED, 0, 0, saved_view(), NULL, NULL, SAVED_KEY, "");
    prev = snode;
    for (int i = 0; i < tri_root_item_count(core); i++) {
        tri_rootitem_t it = tri_root_item_get(core, i);
        if (it.kind == TRI_ROOTITEM_ACCOUNT) prev = add_account_node(it.ref, 0, prev, NODE_ACCOUNT);
        else                                 prev = add_folder_node(it.ref, 0, prev);
    }
    restore_tree_state();
}

static void ensure_tab(view_t *v) {
    if (v->tab) return;
    v->lay_w = -1;
    v->tab = IupCanvas(NULL);
    IupSetAttribute(v->tab, "EXPAND", "YES");
    IupSetAttribute(v->tab, "DBUFFER", "YES");
    IupSetAttribute(v->tab, "SCROLLBAR", "VERTICAL");
    IupSetAttribute(v->tab, "BORDER", "NO");
    IupSetAttribute(v->tab, "FONT", "Sans 9");
    IupSetCallback(v->tab, "ACTION", (Icallback)cb_canvas_action);
    IupSetCallback(v->tab, "SCROLL_CB", (Icallback)cb_canvas_scroll);
    IupSetCallback(v->tab, "WHEEL_CB", (Icallback)cb_canvas_wheel);
    IupSetCallback(v->tab, "BUTTON_CB", (Icallback)cb_canvas_button);
    IupSetCallback(v->tab, "MOTION_CB", (Icallback)cb_canvas_motion);
    IupSetCallback(v->tab, "RESIZE_CB", (Icallback)cb_canvas_resize);
    IupSetCallback(v->tab, "K_cC", (Icallback)cb_canvas_copy);
    char title[200];
    snprintf(title, sizeof title, "%s%s%s", key_name(v->acct), v->target[0] ? "/" : "", v->target[0] ? v->target : "");
    IupSetStrAttribute(v->tab, "TABTITLE", title);
    IupAppend(tabs, v->tab);
    IupMap(v->tab);
    for (int i = 0; i < v->nit; i++)
        for (int m = 0; m < v->items[i].nmedia; m++) v->items[i].media[m]->canvas = v->tab;
    IupRefresh(tabs);
}

static view_t *view_alloc(const char *acct, const char *target) {
    if (nviews >= (int)(sizeof views / sizeof *views)) return &views[0];
    view_t *v = &views[nviews++];
    memset(v, 0, sizeof *v);
    v->items = calloc(VIT_CAP, sizeof *v->items);
    v->item_h = calloc(VIT_CAP, sizeof *v->item_h);
    v->links = calloc(VLINK_CAP, sizeof *v->links);
    snprintf(v->acct, sizeof v->acct, "%s", acct);
    snprintf(v->target, sizeof v->target, "%s", target);
    v->lay_w = -1; v->stick = 1;
    return v;
}

static view_t *view_get(const char *acct, const char *target) {
    view_t *v = view_find(acct, target);
    if (v) return v;
    v = view_alloc(acct, target);
    ensure_tab(v);
    rebuild_tree();
    if (!v->history_loaded) {
        v->history_loaded = 1;
        account_t *a = tri_account_find_by_key(core, acct);
        if (a && target[0]) tri_history_replay(a, target, 200);
    }
    return v;
}

static view_t *inbox_view(void) {
    view_t *v = view_find(INBOX_KEY, "");
    return v ? v : view_alloc(INBOX_KEY, "");
}
static view_t *saved_view(void) {
    view_t *v = view_find(SAVED_KEY, "");
    return v ? v : view_alloc(SAVED_KEY, "");
}

static void saved_view_add(const char *acctkey, const char *target, const char *nick, const char *text, long long ts) {
    char m[700];
    int n = snprintf(m, sizeof m, "[%s%s%s] ", key_name(acctkey), target && target[0] ? "/" : "", target ? target : "");
    if (nick && nick[0]) n += snprintf(m + n, sizeof m - n, "<%s> ", nick);
    snprintf(m + n, sizeof m - n, "%s", text ? text : "");
    view_add(saved_view(), VIT_STATUS, NULL, m, ts);
}

static void saved_view_load(void) {
    const char *ak, *tg, *nk, *tx; long long ts;
    for (int i = 0; tri_saved_get(core, i, &ak, &tg, &nk, &tx, &ts); i++)
        saved_view_add(ak, tg, nk, tx, ts);
}

static void view_dispose(view_t *v) {
    for (int i = 0; i < v->nit; i++) { media_detach(&v->items[i]); free(v->items[i].body); }
    free(v->items); free(v->item_h); free(v->links);
    v->items = NULL; v->item_h = NULL; v->links = NULL; v->nit = 0;
}

static void view_became_current(view_t *v) {
    if (!v) return;

    if (input && current && current != v)
        snprintf(current->draft, sizeof current->draft, "%s", IupGetAttribute(input, "VALUE"));
    if (current != v) reply_clear();
    current = v;
    if (input) IupSetStrAttribute(input, "VALUE", v->draft);
    if (v->unread && v->unread_at < v->nit) v->pending_unread_scroll = 1;
    if (v->tab) IupUpdate(v->tab);
    view_refresh_members();
    attachbar_refresh();
    chrome_sync();
}

static void switch_to(view_t *v) {
    if (!v) return;
    if (!v->tab) { ensure_tab(v); rebuild_tree(); }
    IupSetAttribute(tabs, "VALUE_HANDLE", (char *)v->tab);
    view_became_current(v);
}

static void adopt_shown_tab(void) {
    if (current || nviews == 0) return;
    view_t *nv = view_by_canvas((Ihandle *)IupGetAttribute(tabs, "VALUE_HANDLE"));
    if (nv) current = nv;
}

static void close_tab(view_t *v) {
    if (!v || !v->tab) return;
    Ihandle *t = v->tab;
    v->tab = NULL;
    for (int i = 0; i < v->nit; i++)
        for (int m = 0; m < v->items[i].nmedia; m++) v->items[i].media[m]->canvas = NULL;
    if (current == v) current = NULL;
    IupDestroy(t);
    rebuild_tree();
    adopt_shown_tab();
    view_refresh_members();
    attachbar_refresh();
}

static void drop_view(view_t *v) {
    view_dispose(v);
    if (v->tab) IupDestroy(v->tab);
    view_t *moved = &views[nviews - 1];
    if (current == v) current = NULL;
    else if (current == moved) current = v;
    *v = views[--nviews];
    rebuild_tree();
    adopt_shown_tab();
    view_refresh_members();
    attachbar_refresh();
}

static int cb_tabclose(Ihandle *ih, int pos) {
    (void)ih;
    view_t *v = view_by_canvas(IupGetChild(tabs, pos));
    if (v) close_tab(v);
    return IUP_IGNORE;
}
static int cb_key_closetab(Ihandle *ih) { (void)ih; if (current) close_tab(current); return IUP_DEFAULT; }

static void drop_account_views(const char *acctkey) {
    for (int i = 0; i < nviews; )
        if (!strcmp(views[i].acct, acctkey)) {
            view_dispose(&views[i]);
            IupDestroy(views[i].tab);
            if (current == &views[i]) current = NULL;
            views[i] = views[--nviews];
        } else i++;
    rebuild_tree();
    view_refresh_members();
}

static int cb_members_dblclick(Ihandle *list, int item, char *text) {
    (void)list; (void)item;
    if (!current || !text) return IUP_DEFAULT;
    const char *name = text;
    if (!strncmp(name, "\xE2\x97\x8F ", 4)) name += 4;
    if (!*name) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct);
    char target[320];
    if (a && !strcmp(tri_account_backend(a), "xmpp") && current->target[0])
        snprintf(target, sizeof target, "%s/%s", current->target, name);
    else
        snprintf(target, sizeof target, "%s", name);
    switch_to(view_get(current->acct, target));
    return IUP_DEFAULT;
}

static char g_memuser[128];

static void mem_addr(account_t *a, char *out, size_t n) {
    if (a && !strcmp(tri_account_backend(a), "xmpp") && current && current->target[0])
        snprintf(out, n, "%s/%s", current->target, g_memuser);
    else
        snprintf(out, n, "%s", g_memuser);
}
static int cm_message(Ihandle *ih) {
    (void)ih; if (!current) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct);
    char t[320]; mem_addr(a, t, sizeof t);
    switch_to(view_get(current->acct, t));
    return IUP_DEFAULT;
}
static int cm_profile(Ihandle *ih) {
    (void)ih; if (!current) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct); if (!a) return IUP_DEFAULT;
    char t[320]; mem_addr(a, t, sizeof t);
    if (tri_user_info(a, current->target, t) != 0) IupMessage("Trichat - profile", tri_last_error());
    return IUP_DEFAULT;
}
static int cm_mute(Ihandle *ih) {
    (void)ih; if (!current) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct); if (!a) return IUP_DEFAULT;
    tri_user_set_ignored(a, g_memuser, !tri_user_ignored(a, g_memuser));
    return IUP_DEFAULT;
}

static void cm_moderate(const char *action) {
    if (!current) return;
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (!a) { IupMessage("Trichat", "That account is not connected."); return; }
    const char *be = tri_account_backend(a);
    char arg[256] = "";
    if (!strcmp(action, "ban") && !strcmp(be, "xmpp")) {
        if (!IupGetParam("Ban", NULL, NULL, "Real JID of the user: %s\n", arg, NULL) || !arg[0]) return;
    } else if (!strcmp(action, "kick") || !strcmp(action, "ban")) {
        if (!IupGetParam(action, NULL, NULL, "Reason: %s\n", arg, NULL)) return;
    } else if (!strcmp(action, "move")) {
        if (!IupGetParam("Move user", NULL, NULL, "Destination channel: %s\n", arg, NULL) || !arg[0]) return;
    }
    if (tri_moderate(a, current->target, g_memuser, action, arg[0] ? arg : NULL) != 0)
        IupMessage("Trichat - moderation", tri_last_error());
}
static int cm_kick(Ihandle *ih)   { (void)ih; cm_moderate("kick"); return IUP_DEFAULT; }
static int cm_ban(Ihandle *ih)    { (void)ih; cm_moderate("ban"); return IUP_DEFAULT; }
static int cm_op(Ihandle *ih)     { (void)ih; cm_moderate("op"); return IUP_DEFAULT; }
static int cm_deop(Ihandle *ih)   { (void)ih; cm_moderate("deop"); return IUP_DEFAULT; }
static int cm_voice(Ihandle *ih)  { (void)ih; cm_moderate("voice"); return IUP_DEFAULT; }
static int cm_devoice(Ihandle *ih){ (void)ih; cm_moderate("devoice"); return IUP_DEFAULT; }
static int cm_smute(Ihandle *ih)  { (void)ih; cm_moderate("mute"); return IUP_DEFAULT; }
static int cm_sunmute(Ihandle *ih){ (void)ih; cm_moderate("unmute"); return IUP_DEFAULT; }
static int cm_deaf(Ihandle *ih)   { (void)ih; cm_moderate("deaf"); return IUP_DEFAULT; }
static int cm_move(Ihandle *ih)   { (void)ih; cm_moderate("move"); return IUP_DEFAULT; }

static Ihandle *mod_submenu(const char *be) {
    if (!strcmp(be, "irc"))
        return IupMenu(mk("Kick...", (Icallback)cm_kick), mk("Ban...", (Icallback)cm_ban), IupSeparator(),
                       mk("Op (+o)", (Icallback)cm_op), mk("Deop (-o)", (Icallback)cm_deop),
                       mk("Voice (+v)", (Icallback)cm_voice), mk("Devoice (-v)", (Icallback)cm_devoice),
                       mk("Mute (+q)", (Icallback)cm_smute), mk("Unmute (-q)", (Icallback)cm_sunmute), NULL);
    if (!strcmp(be, "xmpp"))
        return IupMenu(mk("Kick...", (Icallback)cm_kick), mk("Ban...", (Icallback)cm_ban), IupSeparator(),
                       mk("Grant moderator", (Icallback)cm_op),
                       mk("Revoke voice (mute)", (Icallback)cm_smute), mk("Grant voice (unmute)", (Icallback)cm_sunmute), NULL);
    if (!strcmp(be, "mumble"))
        return IupMenu(mk("Kick...", (Icallback)cm_kick), mk("Ban...", (Icallback)cm_ban), IupSeparator(),
                       mk("Server mute", (Icallback)cm_smute), mk("Server unmute", (Icallback)cm_sunmute),
                       mk("Deafen", (Icallback)cm_deaf), mk("Move here / to...", (Icallback)cm_move), NULL);
    return NULL;
}
static void member_context_menu(account_t *a) {
    const char *be = a ? tri_account_backend(a) : "";
    int muted = a && tri_user_ignored(a, g_memuser);
    Ihandle *mod = mod_submenu(be);
    Ihandle *menu = IupMenu(
        mk("Message", (Icallback)cm_message),
        mk(strcmp(be, "irc") ? "Profile" : "WHOIS", (Icallback)cm_profile),
        mk(muted ? "Unmute (local)" : "Mute (local)", (Icallback)cm_mute),
        NULL);
    if (mod) { IupAppend(menu, IupSeparator()); IupAppend(menu, IupSubmenu("Moderation", mod)); }
    IupPopup(menu, IUP_MOUSEPOS, IUP_MOUSEPOS);
    IupDestroy(menu);
}
static int cb_members_button(Ihandle *list, int but, int pressed, int x, int y, char *st) {
    (void)st;
    if (but != IUP_BUTTON3 || pressed || !current || !current->target[0]) return IUP_DEFAULT;
    int pos = IupConvertXYToPos(list, x, y);
    if (pos < 1) return IUP_DEFAULT;
    IupSetInt(list, "VALUE", pos);
    const char *text = IupGetAttributeId(list, "", pos);
    if (!text) return IUP_DEFAULT;
    if (!strncmp(text, "\xE2\x97\x8F ", 4)) text += 4;
    if (!strncmp(text, "[deaf] ", 7)) text += 7;
    else if (!strncmp(text, "[muted] ", 8)) text += 8;
    snprintf(g_memuser, sizeof g_memuser, "%s", text);
    if (!g_memuser[0]) return IUP_DEFAULT;
    member_context_menu(tri_account_find_by_key(core, current->acct));
    return IUP_DEFAULT;
}

enum { CALL_NONE, CALL_RINGING, CALL_INCOMING, CALL_ACTIVE };
static Ihandle *call_dlg, *call_state_lbl, *call_peer_lbl,
               *call_accept_btn, *call_mute_btn, *call_video_btn, *call_screen_btn, *call_hangup_btn,
               *call_vremote, *call_vself, *call_vrow;
static unsigned call_vremote_gen, call_vself_gen;
static struct {
    int   st;
    char  acct[128];
    char  peer[256];
    int   has_video;
    int   muted;
    int   video;
    int   shown;
    long long started;
} g_call;

static int call_canvas_paint(Ihandle *c, int which) {
    int cw = 0, ch = 0; IupGetIntInt(c, "DRAWSIZE", &cw, &ch);
    if (cw <= 0 || ch <= 0) return IUP_DEFAULT;
    IupDrawBegin(c);
    IupSetAttribute(c, "DRAWCOLOR", "20 20 24"); IupSetAttribute(c, "DRAWSTYLE", "FILL");
    IupDrawRectangle(c, 0, 0, cw - 1, ch - 1);
    int w = 0, h = 0; unsigned gen = 0;
    const uint8_t *rgba = g_call.acct[0] ? tri_call_video_frame(core, g_call.acct, which, &w, &h, &gen) : NULL;
    if (rgba && w > 0 && h > 0) {
        const char *name = which == TRI_VIDEO_SELF ? "TRI_VID_SELF" : "TRI_VID_REMOTE";

        static unsigned built_gen[2]; static int built_w[2], built_h[2];
        Ihandle *img = IupGetHandle(name);
        if (!img || gen != built_gen[which] || w != built_w[which] || h != built_h[which]) {
            Ihandle *old = img;
            img = IupImageRGBA(w, h, (unsigned char *)rgba);
            IupSetHandle(name, img);
            if (old) IupDestroy(old);
            built_gen[which] = gen; built_w[which] = w; built_h[which] = h;
        }
        double s = (double)cw / w; if ((double)ch / h < s) s = (double)ch / h;
        int dw = (int)(w * s), dh = (int)(h * s);
        IupDrawImage(c, name, (cw - dw) / 2, (ch - dh) / 2, dw, dh);
    }
    IupDrawEnd(c);
    return IUP_DEFAULT;
}
static int cb_call_canvas_remote(Ihandle *c) { return call_canvas_paint(c, TRI_VIDEO_REMOTE); }
static int cb_call_canvas_self(Ihandle *c)   { return call_canvas_paint(c, TRI_VIDEO_SELF); }

static account_t *call_acct(void) { return g_call.acct[0] ? tri_account_find_by_key(core, g_call.acct) : NULL; }

static void call_ui_sync(void) {
    if (!call_dlg) return;
    IupSetStrAttribute(call_peer_lbl, "TITLE", g_call.peer);
    char st[128];
    if (g_call.st == CALL_INCOMING)      snprintf(st, sizeof st, "Incoming %s call", g_call.has_video ? "video" : "voice");
    else if (g_call.st == CALL_RINGING)  snprintf(st, sizeof st, "Calling\xE2\x80\xA6");
    else { long long d = g_call.started ? (long long)time(NULL) - g_call.started : 0;
           snprintf(st, sizeof st, "In call   %02lld:%02lld", d / 60, d % 60); }
    IupSetStrAttribute(call_state_lbl, "TITLE", st);
    int incoming = g_call.st == CALL_INCOMING, active = g_call.st == CALL_ACTIVE;
    IupSetAttribute(call_accept_btn, "ACTIVE", incoming ? "YES" : "NO");
    IupSetAttribute(call_mute_btn,   "ACTIVE", active ? "YES" : "NO");
    IupSetStrAttribute(call_mute_btn, "TITLE", g_call.muted ? "Unmute" : "Mute");
    int vid = active && g_call.has_video;
    IupSetAttribute(call_video_btn,  "ACTIVE", vid ? "YES" : "NO");
    IupSetStrAttribute(call_video_btn, "TITLE", g_call.video == 1 ? "Stop video" : "Start video");
    IupSetAttribute(call_screen_btn, "ACTIVE", vid ? "YES" : "NO");
    IupSetStrAttribute(call_screen_btn, "TITLE", g_call.video == 2 ? "Stop share" : "Share screen");
    IupSetStrAttribute(call_hangup_btn, "TITLE", incoming ? "Decline" : "Hang up");
}

static int cb_call_accept(Ihandle *h) { (void)h; account_t *a = call_acct();
    if (a && tri_call(a, g_call.peer, TRI_CALL_ACCEPT) != 0) IupMessage("Trichat - accept", tri_last_error());
    return IUP_DEFAULT; }
static int cb_call_hangup(Ihandle *h) { (void)h; account_t *a = call_acct();
    if (a && tri_call(a, g_call.peer, TRI_CALL_HANGUP) != 0) IupMessage("Trichat - hangup", tri_last_error());
    return IUP_DEFAULT; }
static int cb_call_mute(Ihandle *h) { (void)h; account_t *a = call_acct(); if (!a) return IUP_DEFAULT;
    int want_muted = !g_call.muted;
    if (tri_mic(a, !want_muted) != 0) { IupMessage("Trichat - mic", tri_last_error()); return IUP_DEFAULT; }
    g_call.muted = want_muted; call_ui_sync(); return IUP_DEFAULT; }
static int cb_call_video(Ihandle *h) { (void)h; account_t *a = call_acct(); if (!a) return IUP_DEFAULT;
    int act = g_call.video == 1 ? TRI_CALL_VIDEO_STOP : TRI_CALL_VIDEO;
    if (tri_call(a, g_call.peer, act) != 0) { IupMessage("Trichat - video", tri_last_error()); return IUP_DEFAULT; }
    g_call.video = g_call.video == 1 ? 0 : 1; call_ui_sync(); return IUP_DEFAULT; }
static int cb_call_screen(Ihandle *h) { (void)h; account_t *a = call_acct(); if (!a) return IUP_DEFAULT;
    int act = g_call.video == 2 ? TRI_CALL_VIDEO_STOP : TRI_CALL_SCREENSHARE;
    if (tri_call(a, g_call.peer, act) != 0) { IupMessage("Trichat - screenshare", tri_last_error()); return IUP_DEFAULT; }
    g_call.video = g_call.video == 2 ? 0 : 2; call_ui_sync(); return IUP_DEFAULT; }

static void call_ui_build(void) {
    if (call_dlg) return;
    call_state_lbl = IupLabel(""); IupSetAttribute(call_state_lbl, "FONTSTYLE", "Bold");
    call_peer_lbl  = IupLabel(""); IupSetAttribute(call_peer_lbl, "FGCOLOR", "96 96 96");
    call_accept_btn = IupButton("Accept", NULL);       IupSetCallback(call_accept_btn, "ACTION", (Icallback)cb_call_accept);
    call_mute_btn   = IupButton("Mute", NULL);         IupSetCallback(call_mute_btn,   "ACTION", (Icallback)cb_call_mute);
    call_video_btn  = IupButton("Start video", NULL);  IupSetCallback(call_video_btn,  "ACTION", (Icallback)cb_call_video);
    call_screen_btn = IupButton("Share screen", NULL); IupSetCallback(call_screen_btn, "ACTION", (Icallback)cb_call_screen);
    call_hangup_btn = IupButton("Hang up", NULL);      IupSetCallback(call_hangup_btn, "ACTION", (Icallback)cb_call_hangup);
    Ihandle *btns = IupHbox(call_accept_btn, call_mute_btn, call_video_btn, call_screen_btn, call_hangup_btn, NULL);
    IupSetAttribute(btns, "GAP", "4");

    call_vremote = IupCanvas(NULL);
    IupSetAttribute(call_vremote, "EXPAND", "YES");
    IupSetAttribute(call_vremote, "RASTERSIZE", rsz("480x360"));
    IupSetAttribute(call_vremote, "BGCOLOR", "20 20 24");
    IupSetAttribute(call_vremote, "DBUFFER", "YES");
    IupSetCallback(call_vremote, "ACTION", (Icallback)cb_call_canvas_remote);
    call_vself = IupCanvas(NULL);
    IupSetAttribute(call_vself, "RASTERSIZE", rsz("160x120"));
    IupSetAttribute(call_vself, "EXPAND", "VERTICAL");
    IupSetAttribute(call_vself, "BGCOLOR", "20 20 24");
    IupSetAttribute(call_vself, "DBUFFER", "YES");
    IupSetCallback(call_vself, "ACTION", (Icallback)cb_call_canvas_self);
    call_vrow = IupHbox(call_vremote, call_vself, NULL);
    IupSetAttribute(call_vrow, "GAP", "4");
    Ihandle *box = IupVbox(call_state_lbl, call_peer_lbl, call_vrow, btns, NULL);
    IupSetAttribute(box, "MARGIN", "10x10"); IupSetAttribute(box, "GAP", "6");
    call_dlg = IupDialog(box);
    IupSetAttribute(call_dlg, "TITLE", "Call");
    IupSetAttributeHandle(call_dlg, "PARENTDIALOG", dlg);
    IupSetCallback(call_dlg, "CLOSE_CB", (Icallback)cb_call_hangup);
}

static void gcall_on_event(const tri_event_t *ev);

static void call_on_event(const tri_event_t *ev) {
    if (ev->nick && !strncmp(ev->nick, "group", 5)) { gcall_on_event(ev); return; }
    const char *state = ev->text ? ev->text : "";
    int vid = ev->nick && !strcmp(ev->nick, "video");
    if (!strcmp(state, "ended")) {
        g_call.st = CALL_NONE;
        if (call_dlg && g_call.shown) { IupHide(call_dlg); g_call.shown = 0; }
        memset(&g_call, 0, sizeof g_call);
        call_vremote_gen = call_vself_gen = 0;
        return;
    }
    call_ui_build();
    if (ev->account && ev->account != g_call.acct) snprintf(g_call.acct, sizeof g_call.acct, "%s", ev->account);
    if (ev->target  && ev->target  != g_call.peer) snprintf(g_call.peer, sizeof g_call.peer, "%s", ev->target);
    if      (!strcmp(state, "incoming")) { g_call.st = CALL_INCOMING; g_call.has_video = vid; }
    else if (!strcmp(state, "ringing"))  { g_call.st = CALL_RINGING;  g_call.has_video = vid; }
    else if (!strcmp(state, "active"))   { g_call.st = CALL_ACTIVE;   g_call.has_video = vid;
                                           if (!g_call.started) g_call.started = (long long)time(NULL); }
    else return;
    call_ui_sync();

    if (call_vrow) {
        IupSetAttribute(call_vrow, "FLOATING", g_call.has_video ? "NO" : "YES");
        IupSetAttribute(call_vrow, "VISIBLE",  g_call.has_video ? "YES" : "NO");
        IupRefresh(call_dlg);
    }
    if (!g_call.shown) { IupShowXY(call_dlg, IUP_RIGHT, IUP_TOP); g_call.shown = 1; }
}

#define GC_MAX 16
static Ihandle *gcall_dlg, *gcall_state_lbl, *gcall_leave_btn;
static Ihandle *gcall_mute_btn, *gcall_video_btn, *gcall_screen_btn;
static Ihandle *gcall_vself, *gcall_selfrow;
static unsigned gcall_vself_gen;
static struct { Ihandle *tile, *canvas, *name, *mute; } gtiles[GC_MAX];
static tri_call_peer_t gpeer[GC_MAX];
static unsigned gpeer_gen[GC_MAX];
static struct {
    int  shown;
    char acct[128];
    char room[256];
    int  npeer;
    int  muted;
    int  video;
} g_gcall;

static account_t *gcall_acct(void) { return g_gcall.acct[0] ? tri_account_find_by_key(core, g_gcall.acct) : NULL; }

static int cb_gcall_self(Ihandle *c) {
    int cw = 0, ch = 0; IupGetIntInt(c, "DRAWSIZE", &cw, &ch);
    if (cw <= 0 || ch <= 0) return IUP_DEFAULT;
    IupDrawBegin(c);
    IupSetAttribute(c, "DRAWCOLOR", "20 20 24"); IupSetAttribute(c, "DRAWSTYLE", "FILL");
    IupDrawRectangle(c, 0, 0, cw - 1, ch - 1);
    int w = 0, h = 0; unsigned gen = 0;
    const uint8_t *rgba = g_gcall.acct[0] ? tri_call_video_frame(core, g_gcall.acct, TRI_VIDEO_SELF, &w, &h, &gen) : NULL;
    if (rgba && w > 0 && h > 0) {
        Ihandle *img = IupGetHandle("TRI_GSELF");
        static unsigned bg; static int bw, bh;
        if (!img || gen != bg || w != bw || h != bh) {
            Ihandle *old = img;
            img = IupImageRGBA(w, h, (unsigned char *)rgba); IupSetHandle("TRI_GSELF", img);
            if (old) IupDestroy(old); bg = gen; bw = w; bh = h;
        }
        double s = (double)cw / w; if ((double)ch / h < s) s = (double)ch / h;
        int dw = (int)(w * s), dh = (int)(h * s);
        IupDrawImage(c, "TRI_GSELF", (cw - dw) / 2, (ch - dh) / 2, dw, dh);
    }
    IupDrawEnd(c);
    return IUP_DEFAULT;
}

static int cb_gcall_tile(Ihandle *c) {
    int idx = IupGetInt(c, "TRI_TILE_IDX");
    if (idx < 0 || idx >= GC_MAX) return IUP_DEFAULT;
    int cw = 0, ch = 0; IupGetIntInt(c, "DRAWSIZE", &cw, &ch);
    if (cw <= 0 || ch <= 0) return IUP_DEFAULT;
    tri_call_peer_t *pe = &gpeer[idx];
    IupDrawBegin(c);
    IupSetAttribute(c, "DRAWCOLOR", "20 20 24"); IupSetAttribute(c, "DRAWSTYLE", "FILL");
    IupDrawRectangle(c, 0, 0, cw - 1, ch - 1);
    int w = 0, h = 0; unsigned gen = 0;
    const uint8_t *rgba = (pe->video_slot && g_gcall.acct[0])
        ? tri_call_video_frame(core, g_gcall.acct, pe->video_slot, &w, &h, &gen) : NULL;
    if (rgba && w > 0 && h > 0) {
        char name[32]; snprintf(name, sizeof name, "TRI_GTILE_%d", idx);
        static unsigned built_gen[GC_MAX]; static int built_w[GC_MAX], built_h[GC_MAX];
        Ihandle *img = IupGetHandle(name);
        if (!img || gen != built_gen[idx] || w != built_w[idx] || h != built_h[idx]) {
            Ihandle *old = img;
            img = IupImageRGBA(w, h, (unsigned char *)rgba);
            IupSetHandle(name, img);
            if (old) IupDestroy(old);
            built_gen[idx] = gen; built_w[idx] = w; built_h[idx] = h;
        }
        double s = (double)cw / w; if ((double)ch / h < s) s = (double)ch / h;
        int dw = (int)(w * s), dh = (int)(h * s);
        IupDrawImage(c, name, (cw - dw) / 2, (ch - dh) / 2, dw, dh);
    } else {
        char in[2] = { pe->nick[0] ? (char)toupper((unsigned char)pe->nick[0]) : '?', 0 };
        IupSetAttribute(c, "DRAWCOLOR", "48 52 60");
        IupDrawRectangle(c, cw / 2 - 24, ch / 2 - 28, cw / 2 + 24, ch / 2 + 20);
        int tw = 0, th = 0; IupDrawGetTextSize(c, in, 1, &tw, &th);
        IupSetAttribute(c, "DRAWCOLOR", "220 220 220");
        IupDrawText(c, in, 1, (cw - tw) / 2, ch / 2 - 28 + (48 - th) / 2, tw, th);
    }
    if (pe->talking) {
        IupSetAttribute(c, "DRAWCOLOR", "80 200 120"); IupSetAttribute(c, "DRAWSTYLE", "STROKE");
        IupSetAttribute(c, "DRAWLINEWIDTH", "3");
        IupDrawRectangle(c, 1, 1, cw - 2, ch - 2);
    }
    IupDrawEnd(c);
    return IUP_DEFAULT;
}

static void gcall_ui_sync(void) {
    if (!gcall_dlg) return;
    IupSetStrAttribute(gcall_mute_btn,   "TITLE", g_gcall.muted    ? "Unmute" : "Mute");
    IupSetStrAttribute(gcall_video_btn,  "TITLE", g_gcall.video == 1 ? "Stop video" : "Start video");
    IupSetStrAttribute(gcall_screen_btn, "TITLE", g_gcall.video == 2 ? "Stop share" : "Share screen");
    int selfon = g_gcall.video != 0;
    IupSetAttribute(gcall_selfrow, "FLOATING", selfon ? "NO" : "YES");
    IupSetAttribute(gcall_selfrow, "VISIBLE",  selfon ? "YES" : "NO");
    if (!selfon) gcall_vself_gen = 0;
    IupRefresh(gcall_dlg);
}

static int cb_gcall_self_mute(Ihandle *h) { (void)h; account_t *a = gcall_acct(); if (!a) return IUP_DEFAULT;
    int want_muted = !g_gcall.muted;
    if (tri_mic(a, !want_muted) != 0) { IupMessage("Trichat - mic", tri_last_error()); return IUP_DEFAULT; }
    g_gcall.muted = want_muted; gcall_ui_sync(); return IUP_DEFAULT; }
static int cb_gcall_self_video(Ihandle *h) { (void)h; account_t *a = gcall_acct(); if (!a) return IUP_DEFAULT;
    int act = g_gcall.video == 1 ? TRI_CALL_VIDEO_STOP : TRI_CALL_VIDEO;
    if (tri_call(a, g_gcall.room, act) != 0) { IupMessage("Trichat - video", tri_last_error()); return IUP_DEFAULT; }
    g_gcall.video = g_gcall.video == 1 ? 0 : 1; gcall_ui_sync(); return IUP_DEFAULT; }
static int cb_gcall_self_screen(Ihandle *h) { (void)h; account_t *a = gcall_acct(); if (!a) return IUP_DEFAULT;
    int act = g_gcall.video == 2 ? TRI_CALL_VIDEO_STOP : TRI_CALL_SCREENSHARE;
    if (tri_call(a, g_gcall.room, act) != 0) { IupMessage("Trichat - screenshare", tri_last_error()); return IUP_DEFAULT; }
    g_gcall.video = g_gcall.video == 2 ? 0 : 2; gcall_ui_sync(); return IUP_DEFAULT; }

static int cb_gcall_mute(Ihandle *h) {
    int idx = IupGetInt(h, "TRI_TILE_IDX"); account_t *a = gcall_acct();
    if (!a || idx < 0 || idx >= g_gcall.npeer) return IUP_DEFAULT;
    if (tri_call_peer_mute(a, g_gcall.room, gpeer[idx].full, !gpeer[idx].muted) != 0)
        { IupMessage("Trichat - mute", tri_last_error()); return IUP_DEFAULT; }
    return IUP_DEFAULT;
}

static void gcall_teardown(void) {
    if (gcall_dlg && g_gcall.shown) IupHide(gcall_dlg);
    g_gcall.shown = 0;
    memset(&g_gcall, 0, sizeof g_gcall);
    memset(gpeer, 0, sizeof gpeer); memset(gpeer_gen, 0, sizeof gpeer_gen);
    gcall_vself_gen = 0;
}
static int cb_gcall_leave(Ihandle *h) { (void)h; account_t *a = gcall_acct();

    if (a) tri_call(a, g_gcall.room, TRI_CALL_HANGUP);
    gcall_teardown();
    return IUP_DEFAULT; }

static void gcall_ui_build(void) {
    if (gcall_dlg) return;
    gcall_state_lbl = IupLabel(""); IupSetAttribute(gcall_state_lbl, "FONTSTYLE", "Bold");

    Ihandle *rows[4];
    for (int r = 0; r < 4; r++) {
        Ihandle *cells[5]; int nc = 0;
        for (int col = 0; col < 4; col++) {
            int i = r * 4 + col;
            Ihandle *cv = IupCanvas(NULL);
            IupSetAttribute(cv, "RASTERSIZE", rsz("200x150"));
            IupSetAttribute(cv, "BGCOLOR", "20 20 24");
            IupSetAttribute(cv, "DBUFFER", "YES");
            IupSetInt(cv, "TRI_TILE_IDX", i);
            IupSetCallback(cv, "ACTION", (Icallback)cb_gcall_tile);
            Ihandle *nm = IupLabel(""); IupSetAttribute(nm, "EXPAND", "HORIZONTAL");
            Ihandle *mb = IupButton("Mute", NULL); IupSetInt(mb, "TRI_TILE_IDX", i);
            IupSetCallback(mb, "ACTION", (Icallback)cb_gcall_mute);
            Ihandle *foot = IupHbox(nm, mb, NULL); IupSetAttribute(foot, "GAP", "4");
            Ihandle *tile = IupVbox(cv, foot, NULL); IupSetAttribute(tile, "GAP", "2");
            IupSetAttribute(tile, "FLOATING", "YES"); IupSetAttribute(tile, "VISIBLE", "NO");
            gtiles[i].tile = tile; gtiles[i].canvas = cv; gtiles[i].name = nm; gtiles[i].mute = mb;
            cells[nc++] = tile;
        }
        cells[nc] = NULL;
        rows[r] = IupHbox(cells[0], cells[1], cells[2], cells[3], NULL);
        IupSetAttribute(rows[r], "GAP", "6");
    }
    Ihandle *grid = IupVbox(rows[0], rows[1], rows[2], rows[3], NULL);
    IupSetAttribute(grid, "GAP", "6");
    gcall_mute_btn   = IupButton("Mute", NULL);         IupSetCallback(gcall_mute_btn,   "ACTION", (Icallback)cb_gcall_self_mute);
    gcall_video_btn  = IupButton("Start video", NULL);  IupSetCallback(gcall_video_btn,  "ACTION", (Icallback)cb_gcall_self_video);
    gcall_screen_btn = IupButton("Share screen", NULL); IupSetCallback(gcall_screen_btn, "ACTION", (Icallback)cb_gcall_self_screen);
    gcall_leave_btn = IupButton("Leave", NULL); IupSetCallback(gcall_leave_btn, "ACTION", (Icallback)cb_gcall_leave);
    Ihandle *ctl = IupHbox(gcall_mute_btn, gcall_video_btn, gcall_screen_btn, gcall_leave_btn, NULL);
    IupSetAttribute(ctl, "GAP", "4");

    gcall_vself = IupCanvas(NULL);
    IupSetAttribute(gcall_vself, "RASTERSIZE", rsz("160x120"));
    IupSetAttribute(gcall_vself, "BGCOLOR", "20 20 24");
    IupSetAttribute(gcall_vself, "DBUFFER", "YES");
    IupSetCallback(gcall_vself, "ACTION", (Icallback)cb_gcall_self);
    Ihandle *selflbl = IupLabel("You"); IupSetAttribute(selflbl, "FGCOLOR", "96 96 96");
    gcall_selfrow = IupVbox(selflbl, gcall_vself, NULL); IupSetAttribute(gcall_selfrow, "GAP", "2");
    IupSetAttribute(gcall_selfrow, "FLOATING", "YES"); IupSetAttribute(gcall_selfrow, "VISIBLE", "NO");
    Ihandle *top = IupHbox(gcall_state_lbl, IupFill(), gcall_selfrow, NULL);
    IupSetAttribute(top, "ALIGNMENT", "ACENTER");
    Ihandle *box = IupVbox(top, grid, ctl, NULL);
    IupSetAttribute(box, "MARGIN", "10x10"); IupSetAttribute(box, "GAP", "8");
    gcall_dlg = IupDialog(box);
    IupSetAttribute(gcall_dlg, "TITLE", "Group call");

    IupSetAttribute(gcall_dlg, "MINSIZE", "600x420");
    IupSetAttributeHandle(gcall_dlg, "PARENTDIALOG", dlg);
    IupSetCallback(gcall_dlg, "CLOSE_CB", (Icallback)cb_gcall_leave);
}

static void gcall_refresh(void) {
    if (!gcall_dlg || !g_gcall.shown) return;
    account_t *a = gcall_acct();
    tri_call_peer_t cur[GC_MAX];
    int n = a ? tri_call_peers(a, g_gcall.room, cur, GC_MAX) : 0;
    int structural = (n != g_gcall.npeer);
    for (int i = 0; i < GC_MAX; i++) {
        if (i < n) {
            tri_call_peer_t *pe = &cur[i], *old = &gpeer[i];
            if (strcmp(pe->full, old->full)) structural = 1;
            int talk_changed = pe->talking != old->talking;
            int mute_changed = pe->muted   != old->muted;
            unsigned g = 0;
            if (pe->video_slot) tri_call_video_frame(core, g_gcall.acct, pe->video_slot, NULL, NULL, &g);
            int frame_changed = g != gpeer_gen[i];
            *old = *pe;
            if (structural || mute_changed) {
                char nm[96]; snprintf(nm, sizeof nm, "%s%s", pe->nick, pe->connected ? "" : " (\xE2\x80\xA6)");
                IupSetStrAttribute(gtiles[i].name, "TITLE", nm);
                IupSetStrAttribute(gtiles[i].mute, "TITLE", pe->muted ? "Unmute" : "Mute");
                IupSetAttribute(gtiles[i].tile, "FLOATING", "NO");
                IupSetAttribute(gtiles[i].tile, "VISIBLE", "YES");
            }
            if (talk_changed || frame_changed) { gpeer_gen[i] = g; IupUpdate(gtiles[i].canvas); }
        } else if (g_gcall.npeer > i || structural) {
            memset(&gpeer[i], 0, sizeof gpeer[i]); gpeer_gen[i] = 0;
            IupSetAttribute(gtiles[i].tile, "FLOATING", "YES");
            IupSetAttribute(gtiles[i].tile, "VISIBLE", "NO");
        }
    }
    g_gcall.npeer = n;
    if (g_gcall.video) {
        unsigned sg = 0; tri_call_video_frame(core, g_gcall.acct, TRI_VIDEO_SELF, NULL, NULL, &sg);
        if (sg != gcall_vself_gen) { gcall_vself_gen = sg; IupUpdate(gcall_vself); }
    }
    char st[128];
    snprintf(st, sizeof st, "Group call - %d participant%s", n, n == 1 ? "" : "s");
    IupSetStrAttribute(gcall_state_lbl, "TITLE", st);
    if (structural) IupRefresh(gcall_dlg);
}

static void gcall_on_event(const tri_event_t *ev) {
    const char *state = ev->text ? ev->text : "";
    if (!strcmp(state, "ended")) { gcall_teardown(); return; }
    if (strcmp(state, "active")) return;
    gcall_ui_build();

    if (ev->account && ev->account != g_gcall.acct) snprintf(g_gcall.acct, sizeof g_gcall.acct, "%s", ev->account);
    if (ev->target  && ev->target  != g_gcall.room) snprintf(g_gcall.room, sizeof g_gcall.room, "%s", ev->target);
    if (!g_gcall.shown) {
        g_gcall.muted = 0;
        g_gcall.video = (ev->nick && !strcmp(ev->nick, "groupvideo")) ? 1 : 0;
        IupShowXY(gcall_dlg, IUP_CENTER, IUP_CENTER); g_gcall.shown = 1;
    }
    gcall_ui_sync();
    gcall_refresh();
}

static Ihandle *top_call_btn, *top_video_btn;
static int cb_topcall(Ihandle *h) { (void)h;
    if (!current || !current->target[0]) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (a && tri_call(a, current->target, TRI_CALL_START) != 0) IupMessage("Trichat - call", tri_last_error());
    return IUP_DEFAULT; }
static int cb_topvideo(Ihandle *h) { (void)h;
    if (!current || !current->target[0]) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (a && tri_call(a, current->target, TRI_CALL_VIDEO) != 0) IupMessage("Trichat - video", tri_last_error());
    return IUP_DEFAULT; }

static int view_member_count(view_t *v) {
    if (!v || !v->target[0]) return 0;
    int n = 0;
    for (int i = 0; i < tri_roster_count(core); i++) {
        const char *ak = NULL, *ch = NULL, *us = NULL; int tk = 0; tri_roster_get(core, i, &ak, &ch, &us, &tk);
        if (!strcmp(ak, v->acct) && !strcmp(ch, v->target)) n++;
    }
    return n;
}

static void chrome_sync(void) {
    static int last_sig = -1;
    static char last_title[192], last_status[64];
    view_t *v = current;
    char title[192] = "", status[64] = "";
    const char *scolor = "128 128 128";
    account_t *a = NULL;
    int is_special = v && v->acct[0] == '*';
    int is_console = v && v->target[0] == 0;
    int members_n = view_member_count(v);
    const char *proto = "";
    if (v && !is_special) { a = tri_account_find_by_key(core, v->acct); if (a) proto = tri_account_backend(a); }

    if (v && !is_console && (members_n > 0 || (a && tri_target_is_group(a, v->target)))) v->group_latch = 1;
    int is_group = v && !is_console && (v->group_latch || members_n > 0 || (a && tri_target_is_group(a, v->target)));
    int is_xmpp_dm = a && !is_console && !strcmp(proto, "xmpp") && !is_group;
    int online = a && tri_account_state(a) == TRI_CS_ONLINE;

    if (is_special) {
        const char *nm = !strcmp(v->acct, INBOX_KEY) ? "Inbox"
                       : !strcmp(v->acct, SAVED_KEY) ? "Saved messages"
                       : !strcmp(v->acct, ERRORS_KEY) ? "Error log" : "Debug console";
        snprintf(title, sizeof title, "%s", nm);
    } else if (v) {
        if (is_console) snprintf(title, sizeof title, "%s \xC2\xB7 console", key_name(v->acct));
        else            snprintf(title, sizeof title, "%s \xC2\xB7 %s", v->target, proto[0] ? proto : "?");
        if (a) {
            tri_conn_state s = tri_account_state(a);
            if (s == TRI_CS_ONLINE)  { snprintf(status, sizeof status, "\xE2\x97\x8F Online");      scolor = "80 160 80"; }
            else if (s == TRI_CS_CONNECTING) { snprintf(status, sizeof status, "\xE2\x97\x8F Connecting\xE2\x80\xA6"); scolor = "200 150 40"; }
            else { snprintf(status, sizeof status, "\xE2\x97\x8F Offline"); scolor = "150 150 150"; }
        }
        if (members_n > 0) {
            size_t l = strlen(status);
            snprintf(status + l, sizeof status - l, "%s%d member%s", l ? "  \xC2\xB7  " : "", members_n, members_n == 1 ? "" : "s");
        }
    }

    int show_members = members_n > 0;
    int sig = (show_members ? 1 : 0) | (is_xmpp_dm ? 2 : 0) | (v ? 4 : 0) | (online ? 8 : 0);

    if (hdr_title && strcmp(last_title, title))   { snprintf(last_title, sizeof last_title, "%s", title);   IupSetStrAttribute(hdr_title, "TITLE", title); }
    if (hdr_status && strcmp(last_status, status)) { snprintf(last_status, sizeof last_status, "%s", status); IupSetStrAttribute(hdr_status, "TITLE", status); IupSetStrAttribute(hdr_status, "FGCOLOR", scolor); }
    if (top_call_btn)  IupSetAttribute(top_call_btn,  "ACTIVE", online ? "YES" : "NO");
    if (top_video_btn) IupSetAttribute(top_video_btn, "ACTIVE", online ? "YES" : "NO");
    if (omemo_toggle)  IupSetAttribute(omemo_toggle,  "ACTIVE", is_xmpp_dm ? "YES" : "NO");

    if (sig == last_sig) return;
    last_sig = sig;
    if (top_call_btn)  { IupSetAttribute(top_call_btn,  "FLOATING", is_xmpp_dm ? "NO" : "YES"); IupSetAttribute(top_call_btn,  "VISIBLE", is_xmpp_dm ? "YES" : "NO"); }
    if (top_video_btn) { IupSetAttribute(top_video_btn, "FLOATING", is_xmpp_dm ? "NO" : "YES"); IupSetAttribute(top_video_btn, "VISIBLE", is_xmpp_dm ? "YES" : "NO"); }
    if (omemo_toggle)  { IupSetAttribute(omemo_toggle,  "FLOATING", is_xmpp_dm ? "NO" : "YES"); IupSetAttribute(omemo_toggle,  "VISIBLE", is_xmpp_dm ? "YES" : "NO"); }
    if (mempanel)      { IupSetAttribute(mempanel,      "FLOATING", show_members ? "NO" : "YES"); IupSetAttribute(mempanel, "VISIBLE", show_members ? "YES" : "NO"); }
    if (dlg && IupGetAttribute(dlg, "WID")) IupRefresh(dlg);
}

static int members_dirty;
static void on_event(void *ud, const tri_event_t *ev) {
    (void)ud;
    if (ev->kind == TRI_EV_CALL) { call_on_event(ev); return; }
    if (ev->kind == TRI_EV_ROSTER) { members_dirty = 1; return; }
    const char *acct = ev->account ? ev->account : "core";
    const char *target = ev->target ? ev->target : "";

    if (!strcmp(acct, DEBUG_KEY)) { view_t *d = view_find(DEBUG_KEY, ""); if (d) view_add(d, VIT_STATUS, NULL, ev->text, ev->timestamp); return; }

    if (!strcmp(acct, INBOX_KEY)) {
        view_t *ib = inbox_view();
        view_add(ib, VIT_STATUS, NULL, ev->text, ev->timestamp);

        if (!view_is_live(ib) && ib->unread < 2) { ib->unread = 2; color_view_nodes(ib); }

        int n = tri_inbox_count(core);
        const char *ak, *tg, *nk, *tx; long long ts;
        if (n > 0 && tri_inbox_get(core, n - 1, &ak, &tg, &nk, &tx, &ts)) {
            view_t *sv = view_find(ak, tg);
            if (sv && !view_is_live(sv) && sv->unread < 2) { sv->unread = 2; color_view_nodes(sv); }
        }
        return;
    }

    if ((ev->kind == TRI_EV_MESSAGE || ev->kind == TRI_EV_TYPING) && ev->nick) {
        account_t *ia = tri_account_find_by_key(core, acct);
        if (ia && tri_user_ignored(ia, ev->nick)) return;
    }

    if (ev->kind == TRI_EV_TYPING) {
        view_t *tv = view_find(acct, target);
        if (tv) {
            if (ev->text && !strcmp(ev->text, "composing")) {
                snprintf(tv->typing_nick, sizeof tv->typing_nick, "%s", ev->nick ? ev->nick : "");
                tv->typing_at = (long long)time(NULL);
            } else if (ev->nick && !strcmp(tv->typing_nick, ev->nick)) {
                tv->typing_nick[0] = '\0';
            }
        }
        return;
    }

    view_t *v = view_get(acct, target);
    if (ev->history && ev->kind == TRI_EV_MESSAGE && view_has_hist_dup(v, ev->nick, ev->text)) return;
    int kind = ev->kind == TRI_EV_ERROR ? VIT_ERROR : ev->kind == TRI_EV_MESSAGE ? VIT_MSG : VIT_STATUS;
    view_add_enc(v, kind, ev->nick, ev->text, ev->timestamp, ev->encrypted);
    if (ev->kind == TRI_EV_MESSAGE && ev->id && ev->id[0]) snprintf(v->last_msgid, sizeof v->last_msgid, "%s", ev->id);
    if (ev->history) { v->unread_at = v->nit; return; }

    if (ev->kind == TRI_EV_MESSAGE && ev->nick && !strcmp(v->typing_nick, ev->nick)) v->typing_nick[0] = '\0';

    if (ev->kind == TRI_EV_MESSAGE && !view_is_live(v) && v->unread < 1) {
        account_t *va = tri_account_find_by_key(core, v->acct);
        if (!va || tri_channel_notify(va, target) == TRI_NOTIFY_ALL) { v->unread = 1; color_view_nodes(v); }
    }

    view_t *ev_v = view_find(ERRORS_KEY, "");
    if (ev->kind == TRI_EV_ERROR && ev_v && v != ev_v) {
        char m[700]; snprintf(m, sizeof m, "[%s%s%s] %s", key_name(acct), target[0] ? "/" : "", target, ev->text ? ev->text : "");
        view_add(ev_v, VIT_ERROR, NULL, m, ev->timestamp);
    }
    view_t *dv = view_find(DEBUG_KEY, "");
    if (dv && v != dv) {
        const char *kn = ev->kind == TRI_EV_ERROR ? "ERR" : ev->kind == TRI_EV_MESSAGE ? "MSG" : "STA";
        char m[900]; snprintf(m, sizeof m, "%s %s%s%s %s%s%s%s", kn, key_name(acct), target[0] ? "/" : "", target,
                              ev->nick ? "<" : "", ev->nick ? ev->nick : "", ev->nick ? "> " : "", ev->text ? ev->text : "");
        view_add(dv, VIT_STATUS, NULL, m, ev->timestamp);
    }
    if (!current) { current = v; view_refresh_members(); }
}

static Ihandle *form_dlg;
static int form_resize_pending;

static int rebuild_cooldown;

static char g_ct_acct[96], g_ct_target[128];
static int  g_ct_active;
static long long g_ct_last;
static void typing_stop(void) {
    if (!g_ct_active) return;
    g_ct_active = 0;
    account_t *a = tri_account_find_by_key(core, g_ct_acct);
    if (a && g_ct_target[0]) tri_typing(a, g_ct_target, 0);
}

static int cb_timer(Ihandle *t) {
    (void)t; if (!core_alive) return IUP_DEFAULT;
    tri_core_step(core, 0); apply_tree_expansion();
    if (rebuild_cooldown > 0) rebuild_cooldown--;
    if (members_dirty && rebuild_cooldown == 0) {
        members_dirty = 0; rebuild_cooldown = 8; view_refresh_members();
        refresh_channel_occupancy();
    }
    if (form_resize_pending && form_dlg) {
        form_resize_pending = 0;
        IupSetAttribute(form_dlg, "SIZE", NULL);
        IupRefresh(form_dlg);
    }

    static unsigned last_state_hash; static int state_seeded;
    unsigned h = 0;
    for (account_t *a = tri_account_next(core, NULL); a; a = tri_account_next(core, a))
        h = h * 31u + (unsigned)tri_account_state(a) + 7u;

    for (int i = 0; i < tri_chantree_count(core); i++) {
        const char *ak, *nm; unsigned id, par; tri_chantree_get(core, i, &ak, &id, &par, &nm);
        h = h * 131u + id * 2654435761u + par;
        for (const char *p = nm; *p; p++) h = h * 31u + (unsigned char)*p;
        for (const char *p = ak; *p; p++) h = h * 31u + (unsigned char)*p;
    }
    if (!state_seeded) { state_seeded = 1; last_state_hash = h; }
    else if (h != last_state_hash) { last_state_hash = h; rebuild_tree(); }

    if (g_call.st == CALL_ACTIVE) {
        static long long last_dur = -1; long long now = (long long)time(NULL);
        if (now != last_dur) { last_dur = now; call_ui_sync(); }
    }

    if (g_call.st != CALL_NONE && g_call.shown && g_call.has_video && g_call.acct[0]) {
        unsigned g = 0;
        if (tri_call_video_frame(core, g_call.acct, TRI_VIDEO_REMOTE, NULL, NULL, &g) && g != call_vremote_gen) {
            call_vremote_gen = g; if (call_vremote) IupUpdate(call_vremote); }
        g = 0;
        if (tri_call_video_frame(core, g_call.acct, TRI_VIDEO_SELF, NULL, NULL, &g) && g != call_vself_gen) {
            call_vself_gen = g; if (call_vself) IupUpdate(call_vself); }
    }

    if (g_gcall.shown) gcall_refresh();

    if (g_ct_active && (long long)time(NULL) - g_ct_last >= 6) typing_stop();

    static char shown[128];
    char want[128] = "";
    if (current && current->typing_nick[0]) {
        if ((long long)time(NULL) - current->typing_at <= 8)
            snprintf(want, sizeof want, "%s is typing\xE2\x80\xA6", current->typing_nick);
        else current->typing_nick[0] = '\0';
    }
    if (typing_lbl && strcmp(shown, want)) { snprintf(shown, sizeof shown, "%s", want); IupSetStrAttribute(typing_lbl, "TITLE", want); }

    chrome_sync();

    static int last_on = -1;
    int on = 0;
    if (current && current->target[0]) {
        account_t *a = tri_account_find_by_key(core, current->acct);
        if (a && !strcmp(tri_account_backend(a), "xmpp")) on = tri_channel_encrypt(a, current->target);
    }
    if (omemo_toggle && on != last_on) { last_on = on; IupSetAttribute(omemo_toggle, "VALUE", on ? "ON" : "OFF"); }
    return IUP_DEFAULT;
}

static int cb_tabchange(Ihandle *ih, Ihandle *new_tab, Ihandle *old_tab) {
    (void)ih; (void)old_tab;
    view_became_current(view_by_canvas(new_tab));
    return IUP_DEFAULT;
}

static view_t *node_view(int i) {
    if (i < 0) return NULL;
    if (nodemap[i].v) return nodemap[i].v;
    if ((nodemap[i].kind == NODE_ACCOUNT || nodemap[i].kind == NODE_FOLDERACCT) && nodemap[i].acctkey[0])
        return view_get(nodemap[i].acctkey, "");
    if ((nodemap[i].kind == NODE_CHANNEL || nodemap[i].kind == NODE_FOLDERCHANREF) && nodemap[i].acctkey[0] && nodemap[i].target[0])
        return view_get(nodemap[i].acctkey, nodemap[i].target);
    return NULL;
}

static int cb_treeselect(Ihandle *ih, int id, int status) {
    (void)ih;
    if (!status) return IUP_DEFAULT;
    switch_to(node_view(nodemap_find(id)));
    return IUP_DEFAULT;
}

static int cb_treeexec(Ihandle *ih, int id) {
    (void)ih;
    switch_to(node_view(nodemap_find(id)));
    return IUP_DEFAULT;
}

static void echo_self(view_t *v, const char *body) {
    account_t *a = tri_account_find_by_key(core, v->acct);
    int enc = a && v->target[0] && tri_channel_encrypt(a, v->target);
    view_add_enc(v, VIT_SELF, "you", body, 0, enc);
}

static int cb_input_changed(Ihandle *ih) {
    if (!current || !current->target[0]) { typing_stop(); return IUP_DEFAULT; }
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (!a) return IUP_DEFAULT;

    if (g_ct_active && (strcmp(g_ct_acct, current->acct) || strcmp(g_ct_target, current->target))) typing_stop();
    const char *val = IupGetAttribute(ih, "VALUE");
    if (!val || !*val) { typing_stop(); return IUP_DEFAULT; }
    g_ct_last = (long long)time(NULL);
    if (!g_ct_active) {
        snprintf(g_ct_acct, sizeof g_ct_acct, "%s", current->acct);
        snprintf(g_ct_target, sizeof g_ct_target, "%s", current->target);
        tri_typing(a, current->target, 1); g_ct_active = 1;
    }
    return IUP_DEFAULT;
}

static int cb_omemo_toggle(Ihandle *ih, int state) {
    (void)ih;
    if (!current || !current->target[0]) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (a) tri_channel_set_encrypt(a, current->target, state);
    return IUP_DEFAULT;
}

static int ci_prefix(const char *s, const char *pfx, size_t pl) {
    for (size_t i = 0; i < pl; i++) if (tolower((unsigned char)s[i]) != tolower((unsigned char)pfx[i])) return 0;
    return 1;
}
static int cb_input_tab(Ihandle *ih) {
    static int anchor = -1, endpos = -1, suflen = 0, idx = 0;
    static char prefix[64];
    if (!current || !current->target[0]) return IUP_DEFAULT;
    const char *txt = IupGetAttribute(ih, "VALUE"); if (!txt) txt = "";
    int len = (int)strlen(txt);
    int caret = IupGetInt(ih, "CARETPOS"); if (caret < 0 || caret > len) caret = len;

    int cycling = (anchor >= 0 && caret == endpos);
    int ws, we;
    if (cycling) { ws = anchor; we = endpos - suflen; idx++; }
    else { ws = caret; while (ws > 0 && txt[ws - 1] != ' ') ws--; we = caret;
           int wl = we - ws; if (wl > 63) wl = 63; memcpy(prefix, txt + ws, wl); prefix[wl] = '\0'; idx = 0; }

    size_t pl = strlen(prefix);
    char matches[128][64]; int nm = 0;
    for (int i = 0; i < tri_roster_count(core) && nm < 128; i++) {
        const char *ak = NULL, *ch = NULL, *us = NULL; int tk = 0; tri_roster_get(core, i, &ak, &ch, &us, &tk);
        if (strcmp(ak, current->acct) || strcmp(ch, current->target)) continue;
        if (pl && (strlen(us) < pl || !ci_prefix(us, prefix, pl))) continue;
        snprintf(matches[nm++], 64, "%s", us);
    }
    if (nm == 0) { anchor = -1; return IUP_IGNORE; }

    const char *pick = matches[idx % nm];
    const char *suffix = (ws == 0) ? ": " : " ";
    char out[1400];
    int n = snprintf(out, sizeof out, "%.*s%s%s", ws, txt, pick, suffix);
    if (n < 0 || n > (int)sizeof out - 1) n = (int)sizeof out - 1;
    snprintf(out + n, sizeof out - n, "%s", txt + we);
    IupSetStrAttribute(ih, "VALUE", out);
    IupSetInt(ih, "CARETPOS", n);
    anchor = ws; endpos = n; suflen = (int)strlen(suffix);
    return IUP_IGNORE;
}

static int cb_send(Ihandle *ih) {
    const char *raw = IupGetAttribute(ih, "VALUE");
    int has_text = raw && *raw;
    if (!has_text && (!current || current->nattach == 0)) return IUP_DEFAULT;
    if (!current) { IupMessage("Trichat", "Select an account or channel first."); return IUP_DEFAULT; }
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (!a) { IupMessage("Trichat", "That account is no longer connected."); IupSetAttribute(ih, "VALUE", ""); return IUP_DEFAULT; }

    char buf[1400]; snprintf(buf, sizeof buf, "%s", has_text ? raw : "");
    if (buf[0] == '/' && buf[1] != '/') {
        char *cmd = buf + 1, *rest = strchr(cmd, ' ');
        if (rest) *rest++ = '\0';
        char lc[32]; int i; for (i = 0; cmd[i] && i < 31; i++) lc[i] = (char)tolower((unsigned char)cmd[i]); lc[i] = '\0';
        if (!strcmp(lc, "me")) {
            if (!current->target[0]) IupMessage("Trichat", "/me needs an active channel.");
            else if (tri_send_action(a, current->target, rest ? rest : "") != 0) IupMessage("Trichat - /me", tri_last_error());
            else { char l[1400]; snprintf(l, sizeof l, "* you %s", rest ? rest : ""); view_add(current, VIT_STATUS, NULL, l, 0); }
        } else if (!strcmp(lc, "join") || !strcmp(lc, "j")) {
            if (!rest || !*rest) IupMessage("Trichat", "usage: /join <channel>");
            else if (tri_join(a, rest) != 0) IupMessage("Trichat - join", tri_last_error());
        } else if (!strcmp(lc, "part") || !strcmp(lc, "leave")) {
            const char *tgt = (rest && *rest) ? rest : current->target;
            if (!tgt || !*tgt) IupMessage("Trichat", "usage: /part <channel>");
            else if (tri_leave(a, tgt) != 0) IupMessage("Trichat - part", tri_last_error());
        } else if (!strcmp(lc, "close")) {
            drop_view(current);
        } else if (!strcmp(lc, "call")) {
            const char *tgt = (rest && *rest) ? rest : current->target;
            if (!tgt || !*tgt) IupMessage("Trichat", "usage: /call <jid>");
            else if (tri_call(a, tgt, TRI_CALL_START) != 0) IupMessage("Trichat - call", tri_last_error());
        } else if (!strcmp(lc, "accept")) {
            if (tri_call(a, current->target, TRI_CALL_ACCEPT) != 0) IupMessage("Trichat - accept", tri_last_error());
        } else if (!strcmp(lc, "hangup")) {
            if (tri_call(a, current->target, TRI_CALL_HANGUP) != 0) IupMessage("Trichat - hangup", tri_last_error());
        } else if (!strcmp(lc, "mic")) {
            int on = !(rest && !strcmp(rest, "off"));
            if (tri_mic(a, on) != 0) IupMessage("Trichat - mic", tri_last_error());
        } else if (!strcmp(lc, "video") || !strcmp(lc, "screenshare")) {
            const char *tgt = (rest && *rest) ? rest : current->target;
            int act = !strcmp(lc, "screenshare") ? TRI_CALL_SCREENSHARE : TRI_CALL_VIDEO;
            if (!tgt || !*tgt) IupMessage("Trichat", "usage: /video <jid>");
            else if (tri_call(a, tgt, act) != 0) IupMessage("Trichat - video", tri_last_error());
        } else if (!strcmp(lc, "stopvideo")) {
            if (tri_call(a, current->target, TRI_CALL_VIDEO_STOP) != 0) IupMessage("Trichat - video", tri_last_error());
        } else if (!strcmp(lc, "correct") || !strcmp(lc, "edit")) {
            if (!current->target[0]) IupMessage("Trichat", "/correct works inside a conversation.");
            else if (!rest || !*rest) IupMessage("Trichat", "usage: /correct <new text>");
            else if (tri_correct(a, current->target, rest) == 0) echo_self(current, rest);
            else IupMessage("Trichat - correct", tri_last_error());
        } else if (!strcmp(lc, "react")) {
            if (!current->last_msgid[0]) IupMessage("Trichat", "Nothing to react to here yet.");
            else if (tri_react(a, current->target, current->last_msgid, rest ? rest : "") != 0) IupMessage("Trichat - react", tri_last_error());
        } else if (!strcmp(lc, "msg") || !strcmp(lc, "query")) {
            char *tgt = rest ? strtok(rest, " ") : NULL, *msg = tgt ? strtok(NULL, "") : NULL;
            if (!tgt) IupMessage("Trichat", "usage: /msg <target> <message>");
            else {
                view_t *dv = view_get(current->acct, tgt);
                if (msg && *msg) { if (tri_send(a, tgt, msg) == 0) echo_self(dv, msg); else IupMessage("Trichat - msg", tri_last_error()); }
                switch_to(dv);
            }
        } else {
            char up[32]; int j; for (j = 0; cmd[j] && j < 31; j++) up[j] = (char)toupper((unsigned char)cmd[j]); up[j] = '\0';
            char line[1400]; snprintf(line, sizeof line, "%s%s%s", up, rest ? " " : "", rest ? rest : "");
            if (tri_send_raw(a, line) != 0) IupMessage("Trichat - command", tri_last_error());
        }
    } else {
        if (!current->target[0]) IupMessage("Trichat", "Select a channel tab first, then type to send.");
        else {
            if (has_text) { const char *body = (buf[0] == '/' && buf[1] == '/') ? buf + 1 : buf;
                            char rbuf[1900];
                            if (g_reply_text[0]) {
                                size_t o = 0;
                                for (const char *ln = g_reply_text; *ln; ) {
                                    const char *nl = strchr(ln, '\n'); size_t seglen = nl ? (size_t)(nl - ln) : strlen(ln);
                                    o += snprintf(rbuf + o, o < sizeof rbuf ? sizeof rbuf - o : 0, "> %.*s\n", (int)seglen, ln);
                                    if (o >= sizeof rbuf) break;
                                    ln = nl ? nl + 1 : ln + seglen;
                                }
                                snprintf(rbuf + o, o < sizeof rbuf ? sizeof rbuf - o : 0, "%s", body);
                                body = rbuf;
                            }
                            if (tri_send(a, current->target, body) == 0) echo_self(current, body);
                            else IupMessage("Trichat - send failed", tri_last_error());
                            reply_clear(); }
            queue_flush();
        }
    }
    IupSetAttribute(ih, "VALUE", "");
    g_ct_active = 0;
    return IUP_DEFAULT;
}

static const char *backend_for_url(const char *url) {
    if (!strncmp(url, "mumble://", 9)) return "mumble";
    if (!strncmp(url, "xmpp://", 7) || !strncmp(url, "xmpp+plain://", 13)) return "xmpp";
    if (!strncmp(url, "irc://", 6) || !strncmp(url, "ircs://", 7)) return "irc";
    return NULL;
}

static Ihandle *fld_proto, *fld_name, *fld_server, *fld_port, *fld_user, *fld_pass, *fld_join, *fld_tls, *fld_split;
static Ihandle *lbl_user, *lbl_server, *lbl_pass;
static Ihandle *row_server;

static int form_result;

static int cb_adv_toggle(Ihandle *ih, int state) { (void)ih; (void)state; form_resize_pending = 1; return IUP_DEFAULT; }

static int cb_form_ok(Ihandle *ih)     { (void)ih; form_result = 1; return IUP_CLOSE; }
static int cb_form_cancel(Ihandle *ih) { (void)ih; form_result = 0; return IUP_CLOSE; }

static Ihandle *form_row(const char *label, Ihandle *field) {
    Ihandle *l = IupLabel(label); IupSetAttribute(l, "SIZE", "78x");
    return IupHbox(l, field, NULL);
}

static const char *gv(Ihandle *h) { const char *v = IupGetAttribute(h, "VALUE"); return v ? v : ""; }

static void url_to_fields(const char *url) {
    int proto = 1, tls = 1; const char *rest = url;
    if      (!strncmp(url, "ircs://", 7))        { proto = 1; tls = 1; rest = url + 7; }
    else if (!strncmp(url, "irc://", 6))         { proto = 1; tls = 0; rest = url + 6; }
    else if (!strncmp(url, "xmpp+plain://", 13)) { proto = 2; tls = 0; rest = url + 13; }
    else if (!strncmp(url, "xmpp://", 7))        { proto = 2; tls = 1; rest = url + 7; }
    else if (!strncmp(url, "mumble://", 9))      { proto = 3; tls = 1; rest = url + 9; }
    char buf[400]; snprintf(buf, sizeof buf, "%s", rest);
    char *bq = strchr(buf, '?'); if (bq) *bq = '\0';
    char path[128] = "", user[64] = "", pass[160] = "", port[16] = "";
    char *slash = strchr(buf, '/'); if (slash) { *slash++ = '\0'; snprintf(path, sizeof path, "%s", slash); }
    char *at = strrchr(buf, '@'); char *host = buf;
    if (at) { *at = '\0'; char *c = strchr(buf, ':'); if (c) { *c = '\0'; snprintf(pass, sizeof pass, "%s", c + 1); } snprintf(user, sizeof user, "%s", buf); host = at + 1; }
    char *pc = strchr(host, ':'); if (pc) { *pc = '\0'; snprintf(port, sizeof port, "%s", pc + 1); }
    const char *q = strchr(url, '?');
    IupSetStrAttribute(fld_split, "VALUE", (q && strstr(q, "split")) ? "ON" : "OFF");
    IupSetInt(fld_proto, "VALUE", proto);
    IupSetStrAttribute(fld_port, "VALUE", port);
    IupSetStrAttribute(fld_pass, "VALUE", pass);
    IupSetStrAttribute(fld_tls, "VALUE", tls ? "ON" : "OFF");
    if (proto == 2) {
        char addr[320]; snprintf(addr, sizeof addr, "%s@%s", user, host);
        IupSetStrAttribute(fld_user, "VALUE", addr);
        IupSetStrAttribute(fld_server, "VALUE", "");
    } else {
        IupSetStrAttribute(fld_user, "VALUE", user);
        IupSetStrAttribute(fld_server, "VALUE", host);
        IupSetStrAttribute(fld_join, "VALUE", path);
    }
}

static void fields_to_url(char *url, size_t usz, char *join, size_t jsz) {
    int proto = IupGetInt(fld_proto, "VALUE"), tls = IupGetInt(fld_tls, "VALUE");
    const char *port = gv(fld_port), *pass = gv(fld_pass), *j = gv(fld_join);
    char pp[16] = ""; if (*port) snprintf(pp, sizeof pp, ":%s", port);
    char auth[400];
    join[0] = '\0';
    if (proto == 2) {
        char addr[256]; snprintf(addr, sizeof addr, "%s", gv(fld_user));
        char *at = strchr(addr, '@'); const char *domain = at ? at + 1 : "";
        if (at) *at = '\0';
        if (*pass) snprintf(auth, sizeof auth, "%s:%s", addr, pass); else snprintf(auth, sizeof auth, "%s", addr);
        snprintf(url, usz, "%s://%s@%s%s/", tls ? "xmpp" : "xmpp+plain", auth, domain, pp);
        if (*j) snprintf(join, jsz, "%s", j);
        return;
    }
    const char *server = gv(fld_server), *user = gv(fld_user);
    if (*pass) snprintf(auth, sizeof auth, "%s:%s", user, pass); else snprintf(auth, sizeof auth, "%s", user);
    if (proto == 3)
        snprintf(url, usz, "mumble://%s@%s%s%s%s%s", auth, server, pp, *j ? "/" : "", j,
                 IupGetInt(fld_split, "VALUE") ? "?split" : "");
    else
        snprintf(url, usz, "%s://%s@%s%s%s%s", tls ? "ircs" : "irc", auth, server, pp, *j ? "/" : "", j);
}

static Ihandle *lbl_join, *lbl_port;
static Ihandle *form_row_l(const char *label, Ihandle *field, Ihandle **out) {
    Ihandle *l = IupLabel(label); IupSetAttribute(l, "SIZE", "78x"); if (out) *out = l;
    return IupHbox(l, field, NULL);
}
static void proto_sync(void) {
    int p = IupGetInt(fld_proto, "VALUE");
    int irc = (p == 1), xmpp = (p == 2), mumble = (p == 3);
    IupSetStrAttribute(lbl_user, "TITLE", xmpp ? "Address:" : irc ? "Nickname:" : "Username:");
    IupSetStrAttribute(fld_user, "TIP", xmpp ? "Your full XMPP address, e.g. you@example.com"
                                             : irc ? "Your IRC nickname" : "Your Mumble username");

    IupSetStrAttribute(lbl_pass, "TITLE", xmpp ? "Password:" : "Password (optional):");

    IupSetAttribute(row_server, "FLOATING", xmpp ? "YES" : "NO");
    IupSetAttribute(row_server, "VISIBLE", xmpp ? "NO" : "YES");

    IupSetAttribute(fld_tls, "ACTIVE", mumble ? "NO" : "YES");
    IupSetStrAttribute(fld_tls, "TITLE", irc ? "Use TLS (ircs://)"
                                             : xmpp ? "Use TLS (STARTTLS)"
                                                    : "Encrypted (Mumble is always TLS)");
    if (mumble) IupSetAttribute(fld_tls, "VALUE", "ON");
    IupSetAttribute(fld_split, "FLOATING", mumble ? "NO" : "YES");
    IupSetAttribute(fld_split, "VISIBLE", mumble ? "YES" : "NO");
    IupSetStrAttribute(lbl_join, "TITLE", xmpp ? "Room:" : irc ? "Channels:" : "Channel:");
    IupSetStrAttribute(lbl_port, "TITLE", irc ? "Port (6697):" : xmpp ? "Port (5222):" : "Port (64738):");
    if (form_dlg) IupRefresh(form_dlg);
}
static int cb_proto_changed(Ihandle *ih, char *t, int item, int state) { (void)ih; (void)t; (void)item; (void)state; proto_sync(); return IUP_DEFAULT; }

#define MAX_PICK 256
static tri_folder_t *pick_folders[MAX_PICK];
static char pick_paths[MAX_PICK][256];
static int npick;
static void collect_children(tri_folder_t *f, const char *prefix) {
    int n = tri_folder_item_count(f);
    for (int i = 0; i < n; i++) {
        tri_folder_item_t it = tri_folder_item_get(f, i);
        if (it.kind != TRI_ITEM_FOLDER || npick >= MAX_PICK) continue;
        snprintf(pick_paths[npick], sizeof pick_paths[npick], "%s%s", prefix, tri_folder_name(it.folder));
        pick_folders[npick] = it.folder; npick++;
        char sub[256]; snprintf(sub, sizeof sub, "%s%s / ", prefix, tri_folder_name(it.folder));
        collect_children(it.folder, sub);
    }
}
static void collect_folders(void) {
    npick = 0;
    for (int i = 0; i < tri_root_item_count(core); i++) {
        tri_rootitem_t r = tri_root_item_get(core, i);
        if (r.kind != TRI_ROOTITEM_FOLDER || npick >= MAX_PICK) continue;
        snprintf(pick_paths[npick], sizeof pick_paths[npick], "%s", tri_folder_name(r.ref));
        pick_folders[npick] = r.ref; npick++;
        char sub[256]; snprintf(sub, sizeof sub, "%s / ", tri_folder_name(r.ref));
        collect_children(r.ref, sub);
    }
}

static void folder_param_list(char *buf, size_t n, const char *first) {
    collect_folders();
    int k = snprintf(buf, n, "%s", first);
    for (int i = 0; i < npick && k < (int)n; i++) k += snprintf(buf + k, n - k, "|%s", pick_paths[i]);
}
static tri_folder_t *folder_by_listidx(int idx  ) {
    return (idx <= 0 || idx - 1 >= npick) ? NULL : pick_folders[idx - 1];
}

static Ihandle *fld_folder;
static tri_folder_t *sel_folder;
static void folder_dropdown_fill(Ihandle *list, tri_folder_t *preselect) {
    collect_folders();
    IupSetAttribute(list, "REMOVEITEM", "ALL");
    IupSetStrAttribute(list, "APPENDITEM", "None (root)");
    int sel = 1;
    for (int i = 0; i < npick; i++) {
        IupSetStrAttribute(list, "APPENDITEM", pick_paths[i]);
        if (pick_folders[i] == preselect) sel = i + 2;
    }
    IupSetInt(list, "VALUE", sel);
}

static int run_account_dialog(const char *title, const char *pre_name, const char *pre_url,
                              tri_folder_t *pre_folder, tri_folder_t **out_folder,
                              char *out_name, size_t nsz, char *out_url, size_t usz, char *out_join, size_t jsz) {
    fld_proto = IupList(NULL);
    IupSetAttribute(fld_proto, "DROPDOWN", "YES");
    IupSetAttribute(fld_proto, "1", "IRC"); IupSetAttribute(fld_proto, "2", "XMPP"); IupSetAttribute(fld_proto, "3", "Mumble");
    IupSetAttribute(fld_proto, "VALUE", "1"); IupSetAttribute(fld_proto, "VISIBLEITEMS", "4");
    IupSetCallback(fld_proto, "ACTION", (Icallback)cb_proto_changed);
    fld_name = IupText(NULL);   IupSetAttribute(fld_name, "EXPAND", "HORIZONTAL");
    fld_server = IupText(NULL); IupSetAttribute(fld_server, "EXPAND", "HORIZONTAL");
    fld_port = IupText(NULL);   IupSetAttribute(fld_port, "VISIBLECOLUMNS", "6");
    fld_user = IupText(NULL);   IupSetAttribute(fld_user, "EXPAND", "HORIZONTAL");
    fld_pass = IupText(NULL);   IupSetAttribute(fld_pass, "PASSWORD", "YES"); IupSetAttribute(fld_pass, "EXPAND", "HORIZONTAL");
    fld_join = IupText(NULL);   IupSetAttribute(fld_join, "EXPAND", "HORIZONTAL");
    IupSetAttribute(fld_join, "TIP", "Channels to auto-join, comma-separated (e.g. #chan1, #chan2). Channels you join later persist on their own.");
    fld_tls = IupToggle("Use TLS (ircs://)", NULL); IupSetAttribute(fld_tls, "VALUE", "ON");
    fld_split = IupToggle("Per-speaker audio streams (route each user separately)", NULL);
    IupSetAttribute(fld_split, "TIP", "Mumble: give every speaker their own PulseAudio/PipeWire stream, so you can route individual users to OBS, a pngtuber, etc.");
    fld_folder = IupList(NULL); IupSetAttribute(fld_folder, "DROPDOWN", "YES");
    IupSetAttribute(fld_folder, "EXPAND", "HORIZONTAL"); IupSetAttribute(fld_folder, "VISIBLEITEMS", "8");
    folder_dropdown_fill(fld_folder, pre_folder);
    if (pre_url) url_to_fields(pre_url);
    if (pre_name) IupSetStrAttribute(fld_name, "VALUE", pre_name);

    Ihandle *ok = IupButton("OK", NULL), *cancel = IupButton("Cancel", NULL);
    IupSetCallback(ok, "ACTION", (Icallback)cb_form_ok);
    IupSetCallback(cancel, "ACTION", (Icallback)cb_form_cancel);

    row_server = form_row_l("Server:", fld_server, &lbl_server);
    Ihandle *simple = IupVbox(
        form_row("Protocol:", fld_proto),
        form_row_l("Nickname:", fld_user, &lbl_user),
        row_server,
        form_row_l("Password:", fld_pass, &lbl_pass),
        NULL);
    IupSetAttribute(simple, "GAP", "6");

    Ihandle *adv = IupVbox(
        form_row("Account label:", fld_name),
        form_row_l("Port:", fld_port, &lbl_port),
        fld_tls,
        form_row_l("Channel:", fld_join, &lbl_join),
        fld_split,
        form_row("File into folder:", fld_folder),
        NULL);
    IupSetAttribute(adv, "GAP", "6"); IupSetAttribute(adv, "NMARGIN", "0x6");
    Ihandle *exp = IupExpander(adv);
    IupSetAttribute(exp, "TITLE", "Advanced"); IupSetAttribute(exp, "STATE", "CLOSE");
    IupSetCallback(exp, "OPENCLOSE_CB", (Icallback)cb_adv_toggle);

    Ihandle *box = IupVbox(simple, exp, IupHbox(IupFill(), ok, cancel, NULL), NULL);
    IupSetAttribute(box, "MARGIN", "10x10"); IupSetAttribute(box, "GAP", "8");
    Ihandle *d = IupDialog(box);
    IupSetStrAttribute(d, "TITLE", title);
    IupSetAttribute(d, "MINSIZE", "380x");
    form_dlg = d;
    proto_sync();
    form_result = 0;
    IupPopup(d, IUP_CENTER, IUP_CENTER);
    if (form_result) {
        const char *label = gv(fld_name);
        if (!*label) label = gv(fld_user);
        snprintf(out_name, nsz, "%s", label);
        fields_to_url(out_url, usz, out_join, jsz);
        sel_folder = folder_by_listidx(IupGetInt(fld_folder, "VALUE") - 1);
        if (out_folder) *out_folder = sel_folder;
    }
    form_dlg = NULL;
    IupDestroy(d);
    return form_result;
}

static void do_add_account(tri_folder_t *pre_folder) {
    char name[64], url[256], join[128];
    tri_folder_t *dest = NULL;
    if (!run_account_dialog("Add account", NULL, NULL, pre_folder, &dest, name, sizeof name, url, sizeof url, join, sizeof join)) return;
    if (!name[0]) { IupMessage("Trichat", "Account name is required."); return; }
    const char *backend = backend_for_url(url);
    if (!backend) { IupMessage("Trichat", "Please fill in the server field."); return; }
    account_t *a = tri_connect(core, backend, name, url);
    if (!a) { IupMessage("Trichat - connect failed", tri_last_error()); return; }
    if (dest) tri_account_move_to_folder(a, dest);
    if (join[0]) tri_join(a, join);
    rebuild_tree();
}

static int cb_menu_add(Ihandle *ih) { (void)ih; do_add_account(NULL); return IUP_DEFAULT; }

static void join_with_folder(account_t *a) {
    if (!a) return;
    char fl[2048]; folder_param_list(fl, sizeof fl, "None");
    char fmt[2400]; snprintf(fmt, sizeof fmt, "Channel / room: %%s\nFile into folder: %%l|%s|\n", fl);
    char chan[128] = ""; int fidx = 0;
    if (!IupGetParam("Join", NULL, NULL, fmt, chan, &fidx, NULL) || !chan[0]) return;
    if (tri_join(a, chan) != 0) { IupMessage("Trichat - join failed", tri_last_error()); return; }
    tri_folder_t *dest = folder_by_listidx(fidx);
    if (dest) tri_folder_ref_add(dest, tri_account_key(a), chan);
    rebuild_tree();
}

static int cb_menu_join(Ihandle *ih) {
    (void)ih;
    if (!current) { IupMessage("Trichat", "Select an account or channel tab first."); return IUP_DEFAULT; }
    join_with_folder(tri_account_find_by_key(core, current->acct));
    return IUP_DEFAULT;
}

static void open_dm(account_t *a) {
    if (!a) return;
    char jid[160] = "";
    if (!IupGetParam("Direct message", NULL, NULL, "User (JID / nick): %s\n", jid, NULL) || !jid[0]) return;
    switch_to(view_get(tri_account_key(a), jid));
}
static int cb_menu_dm(Ihandle *ih) {
    (void)ih;
    if (!current) { IupMessage("Trichat", "Select an account first."); return IUP_DEFAULT; }
    open_dm(tri_account_find_by_key(core, current->acct));
    return IUP_DEFAULT;
}

static void remove_account(account_t *a) {
    drop_account_views(tri_account_key(a));
    tri_account_remove(core, a);
}
static void edit_account(account_t *a) {
    char curname[64], curcfg[256];
    snprintf(curname, sizeof curname, "%s", tri_account_name(a));
    snprintf(curcfg, sizeof curcfg, "%s", tri_account_config(a));
    tri_folder_t *cur_folder = tri_account_folder(a);
    char name[64], url[256], join[128];
    tri_folder_t *dest = cur_folder;
    if (!run_account_dialog("Edit account", curname, curcfg, cur_folder, &dest, name, sizeof name, url, sizeof url, join, sizeof join)) return;
    const char *backend = backend_for_url(url);
    if (!backend) { IupMessage("Trichat", "Please fill in the server field."); return; }
    remove_account(a);
    account_t *na = tri_connect(core, backend, name, url);
    if (!na) { IupMessage("Trichat - reconnect failed", tri_last_error()); return; }
    if (dest) tri_account_move_to_folder(na, dest);
    if (join[0]) tri_join(na, join);
    rebuild_tree();
}

static Ihandle *acct_list;

static account_t *account_at_index(int oneBased) {
    int n = 1;
    for (account_t *a = tri_account_next(core, NULL); a; a = tri_account_next(core, a), n++)
        if (n == oneBased) return a;
    return NULL;
}
static void acct_list_fill(void) {
    IupSetAttribute(acct_list, "REMOVEITEM", "ALL");
    for (account_t *a = tri_account_next(core, NULL); a; a = tri_account_next(core, a)) {
        char label[160]; snprintf(label, sizeof label, "%s: %s", tri_account_backend(a), tri_account_name(a));
        IupSetStrAttribute(acct_list, "APPENDITEM", label);
    }
}

static int cb_acct_add(Ihandle *ih) { (void)ih; do_add_account(NULL); acct_list_fill(); return IUP_DEFAULT; }
static int cb_acct_remove(Ihandle *ih) {
    (void)ih;
    account_t *a = account_at_index(IupGetInt(acct_list, "VALUE"));
    if (!a) { IupMessage("Trichat", "Select an account first."); return IUP_DEFAULT; }
    remove_account(a); acct_list_fill();
    return IUP_DEFAULT;
}
static int cb_acct_edit(Ihandle *ih) {
    (void)ih;
    account_t *a = account_at_index(IupGetInt(acct_list, "VALUE"));
    if (!a) { IupMessage("Trichat", "Select an account first."); return IUP_DEFAULT; }
    edit_account(a); acct_list_fill();
    return IUP_DEFAULT;
}
static int cb_acct_close(Ihandle *ih) { (void)ih; return IUP_CLOSE; }

static int cb_menu_accounts(Ihandle *ih) {
    (void)ih;
    acct_list = IupList(NULL);
    IupSetAttribute(acct_list, "EXPAND", "YES");
    IupSetAttribute(acct_list, "VISIBLELINES", "6");

    Ihandle *badd = IupButton("Add...", NULL), *bedit = IupButton("Edit...", NULL),
            *brem = IupButton("Remove", NULL), *bclose = IupButton("Close", NULL);
    IupSetCallback(badd, "ACTION", (Icallback)cb_acct_add);
    IupSetCallback(bedit, "ACTION", (Icallback)cb_acct_edit);
    IupSetCallback(brem, "ACTION", (Icallback)cb_acct_remove);
    IupSetCallback(bclose, "ACTION", (Icallback)cb_acct_close);

    Ihandle *box = IupVbox(acct_list, IupHbox(badd, bedit, brem, bclose, NULL), NULL);
    IupSetAttribute(box, "MARGIN", "8x8");
    IupSetAttribute(box, "GAP", "6");
    Ihandle *d = IupDialog(box);
    IupSetAttribute(d, "TITLE", "Accounts");
    IupSetAttribute(d, "RASTERSIZE", rsz("340x240"));
    IupMap(d);
    acct_list_fill();
    IupPopup(d, IUP_CENTER, IUP_CENTER);
    IupDestroy(d);
    acct_list = NULL;
    return IUP_DEFAULT;
}

static int cb_menu_quit(Ihandle *ih) { (void)ih; return IUP_CLOSE; }

static int cb_menu_play(Ihandle *ih) {
    (void)ih;
    if (!current) { IupMessage("Trichat", "Connect a Mumble account and select it first."); return IUP_DEFAULT; }
    Ihandle *fd = IupFileDlg();
    IupSetAttribute(fd, "DIALOGTYPE", "OPEN");
    IupSetAttribute(fd, "TITLE", "Soundboard - pick a 48kHz mono 16-bit WAV");
    IupSetAttribute(fd, "EXTFILTER", "WAV files|*.wav|All files|*.*|");
    IupPopup(fd, IUP_CENTER, IUP_CENTER);
    if (IupGetInt(fd, "STATUS") == 0) {
        account_t *a = tri_account_find_by_key(core, current->acct);
        if (a && tri_play(a, IupGetAttribute(fd, "VALUE")) != 0)
            IupMessage("Trichat - soundboard", tri_last_error());
    }
    IupDestroy(fd);
    return IUP_DEFAULT;
}

static int shrink_for_mumble(const char *path, char *outpath, size_t osz) {
    GError *e = NULL;
    GdkPixbuf *pb = gdk_pixbuf_new_from_file(path, &e);
    if (!pb) { if (e) g_error_free(e); return 0; }
    static int uc = 0;
    snprintf(outpath, osz, "%s/upload_%d.jpg", g_mediadir, ++uc);
    const long TARGET = 85 * 1024;
    int w = gdk_pixbuf_get_width(pb), h = gdk_pixbuf_get_height(pb), maxdim = 1024, ok_any = 0;
    for (int attempt = 0; attempt < 6; attempt++) {
        int tw = w, th = h;
        if (tw > maxdim) { th = th * maxdim / (tw ? tw : 1); tw = maxdim; }
        if (th > maxdim) { tw = tw * maxdim / (th ? th : 1); th = maxdim; }
        if (tw < 1) tw = 1; if (th < 1) th = 1;
        GdkPixbuf *sc = (tw != w || th != h) ? gdk_pixbuf_scale_simple(pb, tw, th, GDK_INTERP_BILINEAR) : g_object_ref(pb);
        if (!sc) break;
        int q = 85 - attempt * 10; if (q < 40) q = 40;
        char qs[8]; snprintf(qs, sizeof qs, "%d", q);
        GError *se = NULL;
        gboolean saved = gdk_pixbuf_save(sc, outpath, "jpeg", &se, "quality", qs, NULL);
        g_object_unref(sc);
        if (!saved) { if (se) g_error_free(se); continue; }
        ok_any = 1;
        FILE *f = fopen(outpath, "rb"); long sz = 0; if (f) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }
        if (sz > 0 && sz <= TARGET) { g_object_unref(pb); return 1; }
        maxdim = maxdim * 3 / 4;
    }
    g_object_unref(pb);
    return ok_any;
}

static void echo_self_image(view_t *v, const char *path) {
    view_add(v, VIT_SELF, "you", "", 0);
    vitem_t *it = &v->items[v->nit - 1];
    media_t *m = media_new(v, path);
    if (!m) return;
    FILE *in = fopen(path, "rb"), *out = fopen(m->path, "wb");
    if (in && out) { char b[8192]; size_t r; while ((r = fread(b, 1, sizeof b, in)) > 0) fwrite(b, 1, r, out); }
    if (in) fclose(in); if (out) fclose(out);
    it->media[it->nmedia++] = m;
    finish_media(m, 1);
}
static void do_send_file(const char *path) {
    if (!current || !current->target[0]) { IupMessage("Trichat", "Select a channel or contact first, then attach a file."); return; }
    account_t *a = tri_account_find_by_key(core, current->acct);
    if (!a) { IupMessage("Trichat", "That account is not connected."); return; }
    const char *backend = tri_account_backend(a);
    int is_img = is_img_ext(path, strlen(path));
    const char *base = strrchr(path, '/'); base = base ? base + 1 : path;

    int native = !strcmp(backend, "xmpp") || (!strcmp(backend, "mumble") && is_img);
    if (native) {
        const char *sendpath = path; char tmp[600];
        if (!strcmp(backend, "mumble") && is_img && shrink_for_mumble(path, tmp, sizeof tmp)) sendpath = tmp;
        if (tri_upload(a, current->target, sendpath) != 0) { IupMessage("Trichat - send file", tri_last_error()); return; }
        if (opt_embed && is_img) echo_self_image(current, path);
        else { char m[600]; snprintf(m, sizeof m, "sent file: %s", base); echo_self(current, m); }
        return;
    }

    account_t *provs[16]; int np = 0;
    for (account_t *pv = tri_upload_provider_next(core, NULL); pv && np < 16; pv = tri_upload_provider_next(core, pv)) provs[np++] = pv;
    if (np == 0) { IupMessage("Trichat - send file",
        "No connected XMPP account can host this file.\n\nConnect an XMPP account with file upload (XEP-0363); Trichat then borrows its homeserver to share attachments into IRC and Mumble."); return; }
    account_t *via = provs[0];
    if (np > 1) {
        const char *names[16]; for (int i = 0; i < np; i++) names[i] = tri_account_key(provs[i]);
        int sel = IupListDialog(1, "Upload via which XMPP account?", np, names, 1, 32, np < 8 ? np : 8, NULL);
        if (sel < 0 || sel >= np) return;
        via = provs[sel];
    }
    if (tri_upload_cross(a, current->target, path, via) != 0) { IupMessage("Trichat - send file", tri_last_error()); return; }
    char m[700]; snprintf(m, sizeof m, "uploading %s via %s...", base, tri_account_key(via)); echo_self(current, m);
}

#define QCACHE_MAX (ATTACH_MAX + 4)
typedef struct { char path[600]; Ihandle *img; unsigned char *pix; } qcache_t;
static qcache_t g_qc[QCACHE_MAX]; static int g_nqc;
static long g_thumb_decodes;

static Ihandle *thumb_from_pixbuf(GdkPixbuf *pb, int max, unsigned char **outpix) {
    if (!pb) return NULL;
    int ow = gdk_pixbuf_get_width(pb), oh = gdk_pixbuf_get_height(pb), tw = ow, th = oh;
    if (tw > max) { th = th * max / (tw ? tw : 1); tw = max; }
    if (th > max) { tw = tw * max / (th ? th : 1); th = max; }
    if (tw < 1) tw = 1; if (th < 1) th = 1;
    GdkPixbuf *sc = (tw != ow || th != oh) ? gdk_pixbuf_scale_simple(pb, tw, th, GDK_INTERP_BILINEAR) : g_object_ref(pb);
    if (!sc) return NULL;
    GdkPixbuf *rgba = gdk_pixbuf_get_has_alpha(sc) ? g_object_ref(sc) : gdk_pixbuf_add_alpha(sc, FALSE, 0, 0, 0);
    g_object_unref(sc); if (!rgba) return NULL;
    int rs = gdk_pixbuf_get_rowstride(rgba); const guchar *px = gdk_pixbuf_get_pixels(rgba);
    unsigned char *buf = malloc((size_t)tw * th * 4);
    if (!buf) { g_object_unref(rgba); return NULL; }
    for (int y = 0; y < th; y++) memcpy(buf + (size_t)y * tw * 4, px + (size_t)y * rs, (size_t)tw * 4);
    g_object_unref(rgba);
    Ihandle *img = IupImageRGBA(tw, th, buf);
    if (!img) { free(buf); return NULL; }
    *outpix = buf; return img;
}
static Ihandle *make_qthumb(const char *path, int max, unsigned char **outpix) {
    GError *e = NULL; GdkPixbuf *pb = gdk_pixbuf_new_from_file(path, &e);
    if (!pb) { if (e) g_error_free(e); return NULL; }
    g_thumb_decodes++;
    Ihandle *img = thumb_from_pixbuf(pb, max, outpix);
    g_object_unref(pb); return img;
}

static void qcache_seed(const char *path, GdkPixbuf *pb) {
    if (g_nqc >= QCACHE_MAX) return;
    unsigned char *pix = NULL; Ihandle *img = thumb_from_pixbuf(pb, 48, &pix);
    if (!img) return;
    snprintf(g_qc[g_nqc].path, sizeof g_qc[0].path, "%s", path);
    g_qc[g_nqc].img = img; g_qc[g_nqc].pix = pix; g_nqc++;
}
static int cb_qthumb_click(Ihandle *ih) {
    if (!current) return IUP_DEFAULT;
    int idx = IupGetInt(ih, "QIDX");
    if (idx >= 0 && idx < current->nattach) {
        for (int i = idx; i < current->nattach - 1; i++)
            snprintf(current->attach[i], sizeof current->attach[i], "%s", current->attach[i + 1]);
        current->nattach--;
    }
    attachbar_refresh();
    return IUP_DEFAULT;
}
static void attachbar_refresh(void) {
    if (!attachbar) return;
    Ihandle *ch;
    while ((ch = IupGetChild(attachbar, 0))) { IupDetach(ch); IupDestroy(ch); }
    int mapped = dlg && IupGetAttribute(dlg, "WID");
    int n = current ? current->nattach : 0;

    qcache_t old[QCACHE_MAX]; int nold = g_nqc;
    memcpy(old, g_qc, sizeof old); g_nqc = 0;
    char used[QCACHE_MAX]; memset(used, 0, sizeof used);
    for (int i = 0; i < n; i++) {
        const char *path = current->attach[i];
        const char *base = strrchr(path, '/'); base = base ? base + 1 : path;
        Ihandle *img = NULL; unsigned char *pix = NULL; int reused = 0;
        for (int j = 0; j < nold; j++)
            if (!used[j] && !strcmp(old[j].path, path)) { img = old[j].img; pix = old[j].pix; used[j] = 1; reused = 1; break; }
        if (!reused && is_img_ext(path, strlen(path))) img = make_qthumb(path, 48, &pix);
        if (g_nqc < QCACHE_MAX) { snprintf(g_qc[g_nqc].path, sizeof g_qc[0].path, "%s", path);
                                  g_qc[g_nqc].img = img; g_qc[g_nqc].pix = pix; g_nqc++; }
        Ihandle *thumb;
        if (img) { thumb = IupLabel(NULL); IupSetAttributeHandle(thumb, "IMAGE", img); }
        else { char lbl[40]; snprintf(lbl, sizeof lbl, "%.28s", base); thumb = IupLabel(lbl); }
        char tip[700]; snprintf(tip, sizeof tip, "%s", base);
        IupSetStrAttribute(thumb, "TIP", tip);
        Ihandle *x = IupButton("\xC3\x97", NULL);
        IupSetAttribute(x, "PADDING", "3x0");
        IupSetStrAttribute(x, "TIP", "Remove this attachment");
        IupSetInt(x, "QIDX", i);
        IupSetCallback(x, "ACTION", (Icallback)cb_qthumb_click);
        Ihandle *cell = IupHbox(thumb, x, NULL);
        IupSetAttribute(cell, "ALIGNMENT", "ACENTER");
        IupSetAttribute(cell, "GAP", "1");
        IupAppend(attachbar, cell);
        if (mapped) IupMap(cell);
    }
    for (int j = 0; j < nold; j++) if (!used[j]) { if (old[j].img) IupDestroy(old[j].img); free(old[j].pix); }

    if (attach_clear) { IupSetAttribute(attach_clear, "ACTIVE", n ? "YES" : "NO");
                        IupSetAttribute(attach_clear, "FLOATING", n ? "NO" : "YES");
                        IupSetAttribute(attach_clear, "VISIBLE", n ? "YES" : "NO"); }
    if (attachscroll) IupSetAttribute(attachscroll, "RASTERSIZE", n ? "x66" : "x1");
    if (mapped) IupRefresh(dlg);
}
static void queue_add(const char *path) {
    if (!path || !path[0]) return;
    if (!current || !current->target[0]) { IupMessage("Trichat", "Select a channel or contact first."); return; }
    if (current->nattach >= ATTACH_MAX) { IupMessage("Trichat", "This channel's attachment queue is full."); return; }
    snprintf(current->attach[current->nattach++], sizeof current->attach[0], "%s", path);
    attachbar_refresh();
}
static void queue_flush(void) {
    if (!current) return;
    char pending[ATTACH_MAX][600]; int n = current->nattach;
    for (int i = 0; i < n; i++) snprintf(pending[i], sizeof pending[i], "%s", current->attach[i]);
    current->nattach = 0;
    for (int i = 0; i < n; i++) do_send_file(pending[i]);
    attachbar_refresh();
}
static int cb_attach_clear(Ihandle *ih) { (void)ih; if (current) current->nattach = 0; attachbar_refresh(); return IUP_DEFAULT; }

static int cb_menu_sendfile(Ihandle *ih) {
    (void)ih;
    if (!current || !current->target[0]) { IupMessage("Trichat", "Select a channel or contact first."); return IUP_DEFAULT; }
    Ihandle *fd = IupFileDlg();
    IupSetAttribute(fd, "DIALOGTYPE", "OPEN");
    IupSetAttribute(fd, "MULTIPLEFILES", "YES");
    IupSetAttribute(fd, "TITLE", "Attach file(s) / image(s)");
    IupPopup(fd, IUP_CENTER, IUP_CENTER);
    if (IupGetInt(fd, "STATUS") == 0) {
        const char *val = IupGetAttribute(fd, "VALUE");
        if (val && strchr(val, '|')) {
            char b[8192]; snprintf(b, sizeof b, "%s", val);
            char *dir = strtok(b, "|");
            for (char *nm = strtok(NULL, "|"); nm; nm = strtok(NULL, "|")) {
                char full[700]; snprintf(full, sizeof full, "%s/%s", dir, nm); queue_add(full);
            }
        } else if (val) queue_add(val);
    }
    IupDestroy(fd);
    return IUP_DEFAULT;
}
static int cb_input_dropfiles(Ihandle *ih, const char *filename, int num, int x, int y) {
    (void)ih; (void)num; (void)x; (void)y; queue_add(filename); return IUP_DEFAULT;
}

static int cb_input_paste(Ihandle *ih) {
    (void)ih;
    GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    if (!cb) return IUP_CONTINUE;
    GdkPixbuf *pb = gtk_clipboard_wait_for_image(cb);
    if (pb) {
        static int pc = 0; char path[600];
        snprintf(path, sizeof path, "%s/paste_%d.png", g_mediadir, ++pc);

        GError *e = NULL; gboolean ok = gdk_pixbuf_save(pb, path, "png", &e, "compression", "1", NULL);
        if (e) g_error_free(e);
        if (ok) qcache_seed(path, pb);
        g_object_unref(pb);
        if (ok) queue_add(path);
        return IUP_IGNORE;
    }
    gchar **uris = gtk_clipboard_wait_for_uris(cb);
    if (uris) {
        int added = 0;
        for (int i = 0; uris[i]; i++) { gchar *fn = g_filename_from_uri(uris[i], NULL, NULL);
                                        if (fn) { queue_add(fn); g_free(fn); added = 1; } }
        g_strfreev(uris);
        if (added) return IUP_IGNORE;
    }
    return IUP_CONTINUE;
}
static int cb_menu_imgopts(Ihandle *ih) {
    (void)ih;
    int embed = opt_embed, purge = opt_purge;
    if (IupGetParam("Image settings", NULL, NULL,
                    "Show inline images: %b\nPurge image cache on load/exit: %b\n", &embed, &purge, NULL)) {
        opt_embed = embed; opt_purge = purge;
    }
    return IUP_DEFAULT;
}

static int ctx_node;

static int cx_switch(Ihandle *ih) { (void)ih; switch_to(node_view(nodemap_find(ctx_node))); return IUP_DEFAULT; }

static int cx_leave(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey);
    if (a) tri_leave(a, nodemap[i].target);
    if (nodemap[i].v) drop_view(nodemap[i].v);
    return IUP_DEFAULT;
}
static int cx_join(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    char chan[128] = "";
    if (IupGetParam("Join", NULL, NULL, "Channel / room: %s\n", chan, NULL) && chan[0])
        if (tri_join(a, chan) != 0) IupMessage("Trichat - join failed", tri_last_error());
    return IUP_DEFAULT;
}
static int cx_dm(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    open_dm(tri_account_find_by_key(core, nodemap[i].acctkey));
    return IUP_DEFAULT;
}

static int cx_afflist(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    if (nodemap[i].v) switch_to(nodemap[i].v);
    if (tri_moderate(a, nodemap[i].target, NULL, "afflist", NULL) != 0) IupMessage("Trichat - affiliations", tri_last_error());
    return IUP_DEFAULT;
}

static int room_affiliate(int i, const char *action, const char *title) {
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    char jid[160] = "";
    if (!IupGetParam(title, NULL, NULL, "User's real JID (user@host): %s\n", jid, NULL) || !jid[0]) return IUP_DEFAULT;
    if (tri_moderate(a, nodemap[i].target, NULL, action, jid) != 0) IupMessage("Trichat - affiliation", tri_last_error());
    return IUP_DEFAULT;
}
static int cx_aff_member(Ihandle *ih) { (void)ih; int i = nodemap_find(ctx_node); return i < 0 ? IUP_DEFAULT : room_affiliate(i, "member", "Grant membership"); }
static int cx_aff_admin(Ihandle *ih)  { (void)ih; int i = nodemap_find(ctx_node); return i < 0 ? IUP_DEFAULT : room_affiliate(i, "admin",  "Grant admin"); }
static int cx_aff_owner(Ihandle *ih)  { (void)ih; int i = nodemap_find(ctx_node); return i < 0 ? IUP_DEFAULT : room_affiliate(i, "owner",  "Grant ownership"); }
static int cx_aff_unban(Ihandle *ih)  { (void)ih; int i = nodemap_find(ctx_node); return i < 0 ? IUP_DEFAULT : room_affiliate(i, "unban",  "Unban user"); }

static int cx_enter(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey);
    if (a && tri_join(a, nodemap[i].target) != 0) IupMessage("Trichat - enter failed", tri_last_error());
    return IUP_DEFAULT;
}

static int cx_file(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;

    char acctkey[96], target[128];
    snprintf(acctkey, sizeof acctkey, "%s", nodemap[i].acctkey);
    snprintf(target, sizeof target, "%s", nodemap[i].target);
    char fl[2048]; folder_param_list(fl, sizeof fl, "- pick one -");
    char fmt[2400]; snprintf(fmt, sizeof fmt, "Existing folder: %%l|%s|\nOr new folder: %%s\n", fl);
    int fidx = 0; char newf[64] = "";
    if (!IupGetParam("File channel into folder", NULL, NULL, fmt, &fidx, newf, NULL)) return IUP_DEFAULT;
    tri_folder_t *dest = folder_by_listidx(fidx);
    if (newf[0]) {
        dest = tri_folder_find(core, newf, NULL);
        if (!dest) dest = tri_folder_create(core, newf, NULL);
    }
    if (!dest) { IupMessage("Trichat", "Pick an existing folder or type a new folder name."); return IUP_DEFAULT; }
    if (tri_folder_ref_add(dest, acctkey, target) != 0) IupMessage("Trichat", tri_last_error());
    rebuild_tree();
    return IUP_DEFAULT;
}

static int cx_unfile(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].folder) return IUP_DEFAULT;
    tri_folder_ref_remove(nodemap[i].folder, nodemap[i].acctkey, nodemap[i].target);
    rebuild_tree();
    return IUP_DEFAULT;
}
static int cx_moveacct(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    account_t *a = nodemap[i].account;
    char fl[2048]; folder_param_list(fl, sizeof fl, "Root");
    char fmt[2400]; snprintf(fmt, sizeof fmt, "Move to: %%l|%s|\n", fl);
    int fidx = 0;
    if (!IupGetParam("Move account to folder", NULL, NULL, fmt, &fidx, NULL)) return IUP_DEFAULT;
    tri_account_move_to_folder(a, folder_by_listidx(fidx));
    rebuild_tree();
    return IUP_DEFAULT;
}
static int cx_editacct(Ihandle *ih) { (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT; if (nodemap[i].account) edit_account(nodemap[i].account); return IUP_DEFAULT; }
static int cx_remacct(Ihandle *ih)  { (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT; if (nodemap[i].account) remove_account(nodemap[i].account); return IUP_DEFAULT; }
static int cx_connect(Ihandle *ih)    { (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    if (tri_account_connect(nodemap[i].account) != 0) IupMessage("Trichat - connect", tri_last_error()); rebuild_tree(); return IUP_DEFAULT; }
static int cx_disconnect(Ihandle *ih) { (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    tri_disconnect(nodemap[i].account); rebuild_tree(); return IUP_DEFAULT; }
static int cx_autoconnect(Ihandle *ih){ (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    tri_account_set_autoconnect(nodemap[i].account, !tri_account_autoconnect(nodemap[i].account)); return IUP_DEFAULT; }

static void create_folder_under(tri_folder_t *parent) {
    char name[64] = "";
    if (!IupGetParam("New folder", NULL, NULL, "Name: %s\n", name, NULL) || !name[0]) return;
    if (tri_folder_find(core, name, parent) &&
        !IupAlarm("Trichat", "A folder with that name already exists here. Create another?", "Create", "Cancel", NULL) )
        return;
    if (!tri_folder_create(core, name, parent)) IupMessage("Trichat", tri_last_error());
    rebuild_tree();
}
static int cx_newfolder(Ihandle *ih)    { (void)ih; create_folder_under(NULL); return IUP_DEFAULT; }
static int cx_newsubfolder(Ihandle *ih) { (void)ih; int i = nodemap_find(ctx_node); if (i >= 0) create_folder_under(nodemap[i].folder); return IUP_DEFAULT; }
static int cx_addacct_here(Ihandle *ih) { (void)ih; int i = nodemap_find(ctx_node); if (i >= 0) do_add_account(nodemap[i].folder); return IUP_DEFAULT; }
static int cx_renamefolder(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].folder) return IUP_DEFAULT;
    tri_folder_t *f = nodemap[i].folder;
    char name[64]; snprintf(name, sizeof name, "%s", tri_folder_name(f));
    if (!IupGetParam("Rename folder", NULL, NULL, "Name: %s\n", name, NULL) || !name[0]) return IUP_DEFAULT;
    if (tri_folder_rename(f, name) != 0) IupMessage("Trichat", tri_last_error());
    rebuild_tree();
    return IUP_DEFAULT;
}
static int cx_delfolder(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].folder) return IUP_DEFAULT;
    tri_folder_t *f = nodemap[i].folder;
    int cascade = 0;
    if (!IupGetParam("Delete folder", NULL, NULL, "Delete contents too (accounts return to root): %b\n", &cascade, NULL)) return IUP_DEFAULT;
    tri_folder_delete(f, cascade ? TRI_FOLDER_DELETE_CASCADE : TRI_FOLDER_DELETE_PROMOTE);
    rebuild_tree();
    return IUP_DEFAULT;
}

static int cx_setnick(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    char nick[64]; snprintf(nick, sizeof nick, "%s", tri_channel_nick(a, nodemap[i].target));
    if (IupGetParam("Nick for this room", NULL, NULL, "Display nick (blank = account default; applies on next join): %s\n", nick, NULL))
        tri_channel_set_nick(a, nodemap[i].target, nick);
    return IUP_DEFAULT;
}
static int cx_togglelog(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    tri_channel_set_log(a, nodemap[i].target, tri_channel_log(a, nodemap[i].target) ? 0 : 1);
    return IUP_DEFAULT;
}

static void cx_set_notify(int level) {
    int i = nodemap_find(ctx_node); if (i < 0) return;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return;
    tri_channel_set_notify(a, nodemap[i].target, level);
    if (level != TRI_NOTIFY_ALL && nodemap[i].v && nodemap[i].v->unread == 1) {
        nodemap[i].v->unread = 0; color_view_nodes(nodemap[i].v);
    }
}
static int cx_notify_all(Ihandle *ih)      { (void)ih; cx_set_notify(TRI_NOTIFY_ALL); return IUP_DEFAULT; }
static int cx_notify_mentions(Ihandle *ih) { (void)ih; cx_set_notify(TRI_NOTIFY_MENTIONS); return IUP_DEFAULT; }
static int cx_notify_mute(Ihandle *ih)     { (void)ih; cx_set_notify(TRI_NOTIFY_MUTE); return IUP_DEFAULT; }

static int cx_toggletyping(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    const char *cur = tri_account_faketyping(a);
    int on_here = cur[0] && !strcmp(cur, nodemap[i].target);
    tri_account_set_faketyping(a, on_here ? "" : nodemap[i].target);
    return IUP_DEFAULT;
}
static int cx_toggleencrypt(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey); if (!a) return IUP_DEFAULT;
    tri_channel_set_encrypt(a, nodemap[i].target, !tri_channel_encrypt(a, nodemap[i].target));
    return IUP_DEFAULT;
}

static Ihandle *g_trustlist, *g_trustown;
static char g_trust_acct[96], g_trust_target[128];
static unsigned g_trust_devs[32]; static int g_trust_ndev;

static void trust_fmt_fp(const char *fp, char *out, size_t n) {
    size_t o = 0;
    for (int i = 0; i < 64 && fp[i]; i++) { if (i && i % 8 == 0 && o + 1 < n) out[o++] = ' '; if (o + 1 < n) out[o++] = fp[i]; }
    out[o] = '\0';
}
static void trust_refresh(void) {
    account_t *a = tri_account_find_by_key(core, g_trust_acct); if (!a) return;
    char own[80];
    if (tri_omemo_own_fingerprint(a, own, sizeof own) == 0) {
        char *sp = strchr(own, ' '); char fpf[100]; trust_fmt_fp(sp ? sp + 1 : own, fpf, sizeof fpf);
        char lbl[200]; snprintf(lbl, sizeof lbl, "Your device %.*s:\n%s", sp ? (int)(sp - own) : 0, own, fpf);
        IupSetStrAttribute(g_trustown, "TITLE", lbl);
    }
    IupSetAttribute(g_trustlist, "REMOVEITEM", "ALL");
    tri_omemo_device_t devs[32];
    int n = tri_omemo_devices(a, g_trust_target, devs, 32);
    g_trust_ndev = n > 0 ? n : 0;
    if (n <= 0) { IupSetAttributeId(g_trustlist, "", 1, "(no sessions yet - send an encrypted message first)"); return; }
    for (int i = 0; i < n && i < 32; i++) {
        g_trust_devs[i] = devs[i].device_id;
        const char *ts = devs[i].trust > 0 ? "TRUSTED  " : devs[i].trust < 0 ? "UNTRUSTED" : "undecided";
        char fpf[100]; trust_fmt_fp(devs[i].fingerprint, fpf, sizeof fpf);
        char row[220]; snprintf(row, sizeof row, "[%s] dev %u   %s", ts, devs[i].device_id, fpf);
        IupSetStrAttributeId(g_trustlist, "", i + 1, row);
    }
}
static int cb_trust_set(Ihandle *ih) {
    int sel = IupGetInt(g_trustlist, "VALUE");
    if (sel < 1 || sel > g_trust_ndev) { IupMessage("OMEMO trust", "Select a device first."); return IUP_DEFAULT; }
    account_t *a = tri_account_find_by_key(core, g_trust_acct);
    if (a && tri_omemo_set_trust(a, g_trust_target, g_trust_devs[sel - 1], IupGetInt(ih, "TRUSTVAL")) != 0)
        IupMessage("OMEMO trust", tri_last_error());
    trust_refresh();
    return IUP_DEFAULT;
}
static int cb_trust_close(Ihandle *ih) { (void)ih; return IUP_CLOSE; }

static int cx_omemofp(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0) return IUP_DEFAULT;
    if (!nodemap[i].target[0]) return IUP_DEFAULT;
    snprintf(g_trust_acct, sizeof g_trust_acct, "%s", nodemap[i].acctkey);
    snprintf(g_trust_target, sizeof g_trust_target, "%s", nodemap[i].target);
    g_trustown = IupLabel("");
    g_trustlist = IupList(NULL);
    IupSetAttribute(g_trustlist, "EXPAND", "YES");
    IupSetAttribute(g_trustlist, "VISIBLELINES", "6");
    IupSetAttribute(g_trustlist, "VISIBLECOLUMNS", "44");
    Ihandle *bt = IupButton("Mark trusted", NULL);  IupSetInt(bt, "TRUSTVAL", TRI_TRUST_TRUSTED);   IupSetCallback(bt, "ACTION", (Icallback)cb_trust_set);
    Ihandle *bu = IupButton("Not trusted", NULL);   IupSetInt(bu, "TRUSTVAL", TRI_TRUST_UNTRUSTED); IupSetCallback(bu, "ACTION", (Icallback)cb_trust_set);
    Ihandle *bd = IupButton("Undecided", NULL);     IupSetInt(bd, "TRUSTVAL", TRI_TRUST_UNDECIDED); IupSetCallback(bd, "ACTION", (Icallback)cb_trust_set);
    Ihandle *bc = IupButton("Close", NULL);         IupSetCallback(bc, "ACTION", (Icallback)cb_trust_close);
    Ihandle *box = IupVbox(g_trustown,
        IupLabel("Compare each fingerprint out-of-band, then mark it trusted.\nUntrusted devices are excluded from your encrypted messages."),
        g_trustlist, IupHbox(bt, bu, bd, bc, NULL), NULL);
    IupSetAttribute(box, "MARGIN", "10x10"); IupSetAttribute(box, "GAP", "6");
    Ihandle *d = IupDialog(box);
    IupSetAttribute(d, "TITLE", "OMEMO trust");
    IupSetAttributeHandle(d, "PARENTDIALOG", dlg);
    trust_refresh();
    IupPopup(d, IUP_CENTER, IUP_CENTER);
    IupDestroy(d);
    return IUP_DEFAULT;
}
static int cx_toggleacctlog(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    tri_account_set_log(nodemap[i].account, tri_account_log(nodemap[i].account) == 1 ? 0 : 1);
    return IUP_DEFAULT;
}
static int cx_record(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    const char *home = getenv("HOME");
    time_t t = time(NULL); char ts[32]; strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", localtime(&t));
    char dir[400]; snprintf(dir, sizeof dir, "%s/trichat-recordings/%s", home ? home : "/tmp", ts);
    if (IupGetParam("Record voice", NULL, NULL, "Folder for per-speaker WAVs: %s\n", dir, NULL) && dir[0])
        if (tri_record(nodemap[i].account, dir) != 0) IupMessage("Record", tri_last_error());
    return IUP_DEFAULT;
}
static int cx_stoprecord(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    tri_record(nodemap[i].account, NULL);
    return IUP_DEFAULT;
}
static int cx_selfmute(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    if (tri_moderate(nodemap[i].account, NULL, NULL, "self-mute", NULL) != 0) IupMessage("Trichat - mute", tri_last_error());
    return IUP_DEFAULT;
}
static int cx_selfdeaf(Ihandle *ih) {
    (void)ih; int i = nodemap_find(ctx_node); if (i < 0 || !nodemap[i].account) return IUP_DEFAULT;
    if (tri_moderate(nodemap[i].account, NULL, NULL, "self-deaf", NULL) != 0) IupMessage("Trichat - deafen", tri_last_error());
    return IUP_DEFAULT;
}

static Ihandle *mk(const char *label, Icallback cb) { Ihandle *it = IupItem(label, NULL); IupSetCallback(it, "ACTION", cb); return it; }

static int cb_treeright(Ihandle *ih, int id) {
    (void)ih; ctx_node = id;
    int i = nodemap_find(id);
    Ihandle *menu = NULL;
    int kind = i < 0 ? -1 : nodemap[i].kind;
    switch (kind) {
        case -1:
            menu = IupMenu(mk("New folder...", (Icallback)cx_newfolder),
                           mk("Add account...", (Icallback)cb_menu_add), NULL);
            break;
        case NODE_FOLDER:
            menu = IupMenu(mk("Rename...", (Icallback)cx_renamefolder),
                           mk("New subfolder...", (Icallback)cx_newsubfolder),
                           mk("Add account here...", (Icallback)cx_addacct_here),
                           IupSeparator(), mk("Delete folder...", (Icallback)cx_delfolder), NULL);
            break;
        case NODE_ACCOUNT:
        case NODE_FOLDERACCT: {
            account_t *a = nodemap[i].account;
            int online = a && tri_account_state(a) != TRI_CS_OFFLINE;
            Ihandle *conn = online ? mk("Disconnect", (Icallback)cx_disconnect) : mk("Connect", (Icallback)cx_connect);
            Ihandle *ac = mk("Connect at startup", (Icallback)cx_autoconnect);
            if (a && tri_account_autoconnect(a)) IupSetAttribute(ac, "VALUE", "ON");
            menu = IupMenu(conn, ac, IupSeparator(),
                           mk("Join channel / room...", (Icallback)cx_join),
                           mk("Message user (DM)...", (Icallback)cx_dm),
                           mk("Move to folder...", (Icallback)cx_moveacct), IupSeparator(),
                           mk("Edit account...", (Icallback)cx_editacct), mk("Remove account", (Icallback)cx_remacct), NULL);
            break;
        }
        case NODE_CHANNEL: {
            account_t *ca = tri_account_find_by_key(core, nodemap[i].acctkey);
            int is_xmpp = ca && !strcmp(tri_account_backend(ca), "xmpp");
            Ihandle *aff = !is_xmpp ? NULL : IupSubmenu("Room affiliations", IupMenu(
                mk("List affiliations", (Icallback)cx_afflist), IupSeparator(),
                mk("Grant membership...", (Icallback)cx_aff_member),
                mk("Grant admin...", (Icallback)cx_aff_admin),
                mk("Grant ownership...", (Icallback)cx_aff_owner),
                mk("Unban user...", (Icallback)cx_aff_unban), NULL));
            menu = IupMenu(mk("Switch to", (Icallback)cx_switch), mk("Enter (move here)", (Icallback)cx_enter),
                           mk("File into folder...", (Icallback)cx_file),
                           IupSeparator(), mk("Leave", (Icallback)cx_leave), NULL);
            if (aff) IupInsert(menu, IupGetChild(menu, 3), aff);
            break;
        }
        case NODE_FOLDERCHANREF:
            menu = IupMenu(mk("Switch to", (Icallback)cx_switch), mk("Enter (move here)", (Icallback)cx_enter),
                           IupSeparator(), mk("Leave", (Icallback)cx_leave),
                           mk("Remove from this folder", (Icallback)cx_unfile), NULL);
            break;
        default: return IUP_DEFAULT;
    }

    if (kind == NODE_CHANNEL || kind == NODE_FOLDERCHANREF) {
        account_t *a = tri_account_find_by_key(core, nodemap[i].acctkey);
        IupAppend(menu, IupSeparator());
        if (a && !strcmp(tri_account_backend(a), "xmpp")) {
            IupAppend(menu, mk("Set nick here...", (Icallback)cx_setnick));
            Ihandle *ft = mk("Appear always typing here", (Icallback)cx_toggletyping);
            const char *cur = tri_account_faketyping(a);
            if (cur[0] && !strcmp(cur, nodemap[i].target)) IupSetAttribute(ft, "VALUE", "ON");
            IupAppend(menu, ft);
            Ihandle *enc = mk("Encrypt (OMEMO)", (Icallback)cx_toggleencrypt);
            if (tri_channel_encrypt(a, nodemap[i].target)) IupSetAttribute(enc, "VALUE", "ON");
            IupAppend(menu, enc);
            IupAppend(menu, mk("OMEMO trust / fingerprints...", (Icallback)cx_omemofp));
        }
        Ihandle *lg = mk("Log this channel", (Icallback)cx_togglelog);
        if (a && tri_channel_log(a, nodemap[i].target)) IupSetAttribute(lg, "VALUE", "ON");
        IupAppend(menu, lg);
        int nl = a ? tri_channel_notify(a, nodemap[i].target) : 0;
        Ihandle *n_all = mk("All messages", (Icallback)cx_notify_all);
        Ihandle *n_men = mk("Mentions only", (Icallback)cx_notify_mentions);
        Ihandle *n_mut = mk("Mute", (Icallback)cx_notify_mute);
        IupSetAttribute(nl == TRI_NOTIFY_MUTE ? n_mut : nl == TRI_NOTIFY_MENTIONS ? n_men : n_all, "VALUE", "ON");
        IupAppend(menu, IupSubmenu("Notifications", IupMenu(n_all, n_men, n_mut, NULL)));
    } else if (kind == NODE_ACCOUNT || kind == NODE_FOLDERACCT) {
        account_t *a = nodemap[i].account;
        IupAppend(menu, IupSeparator());
        Ihandle *lg = mk("Log all channels", (Icallback)cx_toggleacctlog);
        if (a && tri_account_log(a) == 1) IupSetAttribute(lg, "VALUE", "ON");
        IupAppend(menu, lg);
        if (a && !strcmp(tri_account_backend(a), "mumble")) {
            IupAppend(menu, mk("Mute myself (toggle)", (Icallback)cx_selfmute));
            IupAppend(menu, mk("Deafen myself (toggle)", (Icallback)cx_selfdeaf));
            IupAppend(menu, mk("Record voice...", (Icallback)cx_record));
            IupAppend(menu, mk("Stop recording", (Icallback)cx_stoprecord));
        }
    }
    IupPopup(menu, IUP_MOUSEPOS, IUP_MOUSEPOS);
    IupDestroy(menu);
    return IUP_DEFAULT;
}

static int cb_tree_button(Ihandle *ih, int but, int pressed, int x, int y, char *st) {
    (void)st;
    if (but != IUP_BUTTON3 || pressed) return IUP_DEFAULT;
    GtkWidget *w = (GtkWidget *)IupGetAttribute(ih, "WID");
    if (GTK_IS_TREE_VIEW(w)) {
        GtkTreePath *path = NULL;
        if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(w), x, y, &path, NULL, NULL, NULL) && path) {
            gtk_tree_view_set_cursor(GTK_TREE_VIEW(w), path, NULL, FALSE);
            gtk_tree_path_free(path);
            return cb_treeright(ih, IupGetInt(ih, "VALUE"));
        }
        if (path) gtk_tree_path_free(path);
        return cb_treeright(ih, -1);
    }
    return cb_treeright(ih, IupGetInt(ih, "VALUE"));
}

static int cb_dragdrop(Ihandle *ih, int drag_id, int drop_id, int isshift, int iscontrol) {
    (void)ih; (void)isshift; (void)iscontrol;
    int di = nodemap_find(drag_id); if (di < 0) return IUP_DEFAULT;
    int oi = nodemap_find(drop_id);
    int dk = nodemap[di].kind;
    int ok = oi < 0 ? -1 : nodemap[oi].kind;

    if (dk == NODE_ACCOUNT || dk == NODE_FOLDERACCT) {
        account_t *a = nodemap[di].account;
        if (ok == NODE_FOLDER) tri_account_move_to_folder(a, nodemap[oi].folder);
        else if (ok == -1)     tri_account_move_to_folder(a, NULL);
        else if (ok == NODE_ACCOUNT || ok == NODE_FOLDERACCT) {
            account_t *b = nodemap[oi].account; if (b == a) return IUP_DEFAULT;
            char name[64] = "";
            if (!IupGetParam("New folder", NULL, NULL, "Folder name: %s\n", name, NULL) || !name[0]) return IUP_DEFAULT;
            tri_folder_t *f = tri_folder_create(core, name, NULL);
            if (f) { tri_account_move_to_folder(a, f); tri_account_move_to_folder(b, f); }
        } else return IUP_DEFAULT;
    } else if (dk == NODE_FOLDER) {
        tri_folder_t *dest = ok == NODE_FOLDER ? nodemap[oi].folder : ok == -1 ? NULL : (tri_folder_t *)-1;
        if (dest == (tri_folder_t *)-1) return IUP_DEFAULT;
        if (tri_folder_move(nodemap[di].folder, dest) != 0) IupMessage("Trichat - move folder", tri_last_error());
    } else if (dk == NODE_CHANNEL) {
        if (ok != NODE_FOLDER) return IUP_DEFAULT;
        if (tri_folder_ref_add(nodemap[oi].folder, nodemap[di].acctkey, nodemap[di].target) != 0) IupMessage("Trichat", tri_last_error());
    } else if (dk == NODE_FOLDERCHANREF) {
        if (ok == -1) tri_folder_ref_remove(nodemap[di].folder, nodemap[di].acctkey, nodemap[di].target);
        else if (ok == NODE_FOLDER) { tri_folder_ref_remove(nodemap[di].folder, nodemap[di].acctkey, nodemap[di].target);
                                      tri_folder_ref_add(nodemap[oi].folder, nodemap[di].acctkey, nodemap[di].target); }
        else return IUP_DEFAULT;
    } else return IUP_DEFAULT;

    rebuild_tree();
    return IUP_DEFAULT;
}

static Ihandle *aud_method, *aud_device;
static const char *const aud_ids[] = { "auto", "pulse", "alsa", "pipewire", "ffplay" };

static void aud_apply(void) {
    int idx = IupGetInt(aud_method, "VALUE");
    const char *m = (idx >= 1 && idx <= 5) ? aud_ids[idx - 1] : "auto";
    tri_audio_set(core, m, gv(aud_device));
}
static int cb_aud_test(Ihandle *ih) { (void)ih; aud_apply(); if (tri_audio_test(core) != 0) IupMessage("Trichat - audio", tri_last_error()); return IUP_DEFAULT; }
static int cb_aud_ok(Ihandle *ih)   { (void)ih; aud_apply(); return IUP_CLOSE; }

static int cb_menu_audio(Ihandle *ih) {
    (void)ih;
    aud_method = IupList(NULL);
    IupSetAttribute(aud_method, "DROPDOWN", "YES");
    IupSetAttribute(aud_method, "1", "Auto (recommended)");
    IupSetAttribute(aud_method, "2", "PulseAudio");
    IupSetAttribute(aud_method, "3", "ALSA");
    IupSetAttribute(aud_method, "4", "PipeWire");
    IupSetAttribute(aud_method, "5", "ffplay");
    IupSetAttribute(aud_method, "VISIBLEITEMS", "6");
    aud_device = IupText(NULL); IupSetAttribute(aud_device, "EXPAND", "HORIZONTAL");

    const char *m, *d; tri_audio_get(core, &m, &d);
    int idx = 1; for (int i = 0; i < 5; i++) if (!strcmp(m, aud_ids[i])) idx = i + 1;
    IupSetInt(aud_method, "VALUE", idx);
    IupSetStrAttribute(aud_device, "VALUE", d);

    Ihandle *test = IupButton("Test sound", NULL); IupSetCallback(test, "ACTION", (Icallback)cb_aud_test);
    Ihandle *ok = IupButton("OK", NULL);           IupSetCallback(ok, "ACTION", (Icallback)cb_aud_ok);
    Ihandle *cancel = IupButton("Cancel", NULL);   IupSetCallback(cancel, "ACTION", (Icallback)cb_form_cancel);
    Ihandle *box = IupVbox(
        form_row("Output:", aud_method), form_row("Device:", aud_device),
        IupLabel("Device optional - blank = system default. Applies to voice you hear."),
        IupHbox(test, IupFill(), ok, cancel, NULL), NULL);
    IupSetAttribute(box, "MARGIN", "10x10"); IupSetAttribute(box, "GAP", "6");
    Ihandle *d2 = IupDialog(box);
    IupSetAttribute(d2, "TITLE", "Audio settings");
    IupSetAttribute(d2, "MINSIZE", "380x");
    IupPopup(d2, IUP_CENTER, IUP_CENTER);
    IupDestroy(d2);
    return IUP_DEFAULT;
}

static int cb_about(Ihandle *ih) {
    (void)ih;
    IupMessage("About Trichat",
        "Trichat - one client for IRC, XMPP and Mumble.\n\n"
        "Part of the Cyberix family.\n"
        "Core in C; GUI via IUP. TLS by wolfSSL.\n"
        "Native, lightweight, multiaccount-first.");
    return IUP_DEFAULT;
}

static void open_special(const char *key, const char *title) {
    view_t *v = view_find(key, "");
    int created = !v;
    if (!v) v = view_get(key, "");
    switch_to(v);
    IupSetStrAttribute(v->tab, "TABTITLE", title);
    IupRefresh(tabs);
    if (created) view_add(v, VIT_STATUS, NULL, title, 0);
}
static int cb_menu_errors(Ihandle *ih) { (void)ih; open_special(ERRORS_KEY, "Error log"); return IUP_DEFAULT; }
static int cb_menu_debug(Ihandle *ih)  { (void)ih; open_special(DEBUG_KEY, "Debug console"); return IUP_DEFAULT; }

static Ihandle *qs_dlg, *qs_filter, *qs_list;
static view_t *qs_rows[256];
static int qs_nrows;

static void str_lower(const char *s, char *out, size_t n) {
    size_t i = 0; for (; s && s[i] && i + 1 < n; i++) out[i] = (char)tolower((unsigned char)s[i]); out[i] = '\0';
}

static void qs_populate(const char *filt) {
    IupSetAttribute(qs_list, "REMOVEITEM", "ALL");
    qs_nrows = 0;
    char lf[128]; str_lower(filt, lf, sizeof lf);
    for (int i = 0; i < nviews && qs_nrows < (int)(sizeof qs_rows / sizeof *qs_rows); i++) {
        view_t *v = &views[i];
        if (v->acct[0] == '*') continue;
        char lbl[192]; snprintf(lbl, sizeof lbl, "%s%s%s", key_name(v->acct), v->target[0] ? "/" : "", v->target);
        if (lf[0]) { char low[192]; str_lower(lbl, low, sizeof low); if (!strstr(low, lf)) continue; }
        qs_rows[qs_nrows++] = v;
        IupSetStrAttribute(qs_list, "APPENDITEM", lbl);
    }
    if (qs_nrows) IupSetInt(qs_list, "VALUE", 1);
}

static void qs_choose(int row) {
    if (row < 1 || row > qs_nrows) return;
    view_t *v = qs_rows[row - 1];
    IupHide(qs_dlg);
    switch_to(v);
    for (int i = 0; i < nnodemap; i++)
        if (nodemap[i].v == v) { IupSetInt(tree, "VALUE", nodemap[i].node); break; }
}

static int cb_qs_changed(Ihandle *ih)   { qs_populate(IupGetAttribute(ih, "VALUE")); return IUP_DEFAULT; }
static int cb_qs_enter(Ihandle *ih)     { (void)ih; qs_choose(IupGetInt(qs_list, "VALUE")); return IUP_DEFAULT; }
static int cb_qs_esc(Ihandle *ih)       { (void)ih; IupHide(qs_dlg); return IUP_DEFAULT; }
static int cb_qs_dblclick(Ihandle *ih, int item, char *t) { (void)ih; (void)t; qs_choose(item); return IUP_DEFAULT; }

static int cb_qs_down(Ihandle *ih) { (void)ih; int v = IupGetInt(qs_list, "VALUE"); if (v < qs_nrows) IupSetInt(qs_list, "VALUE", v + 1); return IUP_IGNORE; }
static int cb_qs_up(Ihandle *ih)   { (void)ih; int v = IupGetInt(qs_list, "VALUE"); if (v > 1) IupSetInt(qs_list, "VALUE", v - 1); return IUP_IGNORE; }

static void quickswitch_open(void) {
    if (!qs_dlg) {
        qs_filter = IupText(NULL);
        IupSetAttribute(qs_filter, "EXPAND", "HORIZONTAL");
        IupSetAttribute(qs_filter, "VISIBLECOLUMNS", "32");
        IupSetCallback(qs_filter, "VALUECHANGED_CB", (Icallback)cb_qs_changed);
        IupSetCallback(qs_filter, "K_CR", (Icallback)cb_qs_enter);
        IupSetCallback(qs_filter, "K_ESC", (Icallback)cb_qs_esc);
        IupSetCallback(qs_filter, "K_UP", (Icallback)cb_qs_up);
        IupSetCallback(qs_filter, "K_DOWN", (Icallback)cb_qs_down);
        qs_list = IupList(NULL);
        IupSetAttribute(qs_list, "EXPAND", "YES");
        IupSetAttribute(qs_list, "VISIBLELINES", "10");
        IupSetAttribute(qs_list, "RASTERSIZE", rsz("260x160"));
        IupSetCallback(qs_list, "DBLCLICK_CB", (Icallback)cb_qs_dblclick);
        Ihandle *box = IupVbox(IupLabel("Jump to conversation:"), qs_filter, qs_list, NULL);
        IupSetAttribute(box, "MARGIN", "8x8");
        IupSetAttribute(box, "GAP", "4");
        qs_dlg = IupDialog(box);
        IupSetAttribute(qs_dlg, "TITLE", "Quick switcher");
        IupSetAttribute(qs_dlg, "MINBOX", "NO");
        IupSetAttribute(qs_dlg, "MAXBOX", "NO");
        IupSetAttributeHandle(qs_dlg, "PARENTDIALOG", dlg);
        IupSetCallback(qs_dlg, "K_ESC", (Icallback)cb_qs_esc);
    }
    IupSetAttribute(qs_filter, "VALUE", "");
    qs_populate("");
    IupShowXY(qs_dlg, IUP_CENTER, IUP_CENTER);
    IupSetFocus(qs_filter);
}
static int cb_key_quickswitch(Ihandle *ih) { (void)ih; quickswitch_open(); return IUP_DEFAULT; }

static Ihandle *sr_dlg, *sr_list, *sr_input, *sr_count;
static struct { view_t *v; int item; } sr_rows[512];
static int sr_nrows;

static const char *ci_strstr(const char *hay, const char *ndl) {
    if (!ndl || !*ndl) return hay;
    for (; *hay; hay++) {
        const char *h = hay, *n = ndl;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) { h++; n++; }
        if (!*n) return hay;
    }
    return NULL;
}

static void sr_choose(int row) {
    if (row < 1 || row > sr_nrows) return;
    view_t *v = sr_rows[row - 1].v; int item = sr_rows[row - 1].item;
    IupHide(sr_dlg);
    switch_to(v);
    v->seek_to = item + 1;
    if (v->tab) { v->lay_w = -1; IupUpdate(v->tab); }
    for (int i = 0; i < nnodemap; i++)
        if (nodemap[i].v == v) { IupSetInt(tree, "VALUE", nodemap[i].node); break; }
}

static int cb_sr_enter(Ihandle *ih)     { (void)ih; sr_choose(IupGetInt(sr_list, "VALUE")); return IUP_DEFAULT; }
static int cb_sr_esc(Ihandle *ih)       { (void)ih; IupHide(sr_dlg); return IUP_DEFAULT; }
static int cb_sr_dblclick(Ihandle *ih, int item, char *t) { (void)ih; (void)t; sr_choose(item); return IUP_DEFAULT; }

static int sr_run(Ihandle *ih) {
    (void)ih;
    const char *q = sr_input ? IupGetAttribute(sr_input, "VALUE") : NULL;
    IupSetAttribute(sr_list, "REMOVEITEM", "ALL");
    sr_nrows = 0;
    if (q && *q)
    for (int i = 0; i < nviews && sr_nrows < (int)(sizeof sr_rows / sizeof *sr_rows); i++) {
        view_t *v = &views[i];
        if (v->acct[0] == '*') continue;
        for (int k = 0; k < v->nit && sr_nrows < (int)(sizeof sr_rows / sizeof *sr_rows); k++) {
            vitem_t *it = &v->items[k];
            if (it->kind != VIT_MSG && it->kind != VIT_SELF) continue;
            if (!it->body || !ci_strstr(it->body, q)) continue;
            char lbl[240];
            snprintf(lbl, sizeof lbl, "%s%s%s  %s%s%.90s", key_name(v->acct), v->target[0] ? "/" : "", v->target,
                     it->nick[0] ? it->nick : "", it->nick[0] ? ": " : "", it->body);
            for (char *p = lbl; *p; p++) if (*p == '\n' || *p == '\t') *p = ' ';
            sr_rows[sr_nrows].v = v; sr_rows[sr_nrows].item = k; sr_nrows++;
            IupSetStrAttribute(sr_list, "APPENDITEM", lbl);
        }
    }
    char c[80]; snprintf(c, sizeof c, (q && *q) ? "%d hit%s" : "Type a query and press Enter", sr_nrows, sr_nrows == 1 ? "" : "s");
    IupSetStrAttribute(sr_count, "TITLE", c);
    if (sr_nrows) IupSetInt(sr_list, "VALUE", 1);
    return IUP_DEFAULT;
}

static int cb_search_open(Ihandle *ih) {
    (void)ih;
    if (!sr_dlg) {
        sr_input = IupText(NULL);
        IupSetAttribute(sr_input, "EXPAND", "HORIZONTAL");
        IupSetAttribute(sr_input, "CUEBANNER", "Search all conversations...");
        IupSetCallback(sr_input, "K_CR", (Icallback)sr_run);
        Ihandle *go = IupButton("Search", NULL);
        IupSetCallback(go, "ACTION", (Icallback)sr_run);
        Ihandle *qrow = IupHbox(sr_input, go, NULL);
        IupSetAttribute(qrow, "GAP", "4"); IupSetAttribute(qrow, "ALIGNMENT", "ACENTER");
        sr_count = IupLabel("Type a query and press Enter");
        IupSetAttribute(sr_count, "FGCOLOR", "96 96 96");
        sr_list = IupList(NULL);
        IupSetAttribute(sr_list, "EXPAND", "YES");
        IupSetAttribute(sr_list, "VISIBLELINES", "14");
        IupSetCallback(sr_list, "DBLCLICK_CB", (Icallback)cb_sr_dblclick);
        IupSetCallback(sr_list, "K_CR", (Icallback)cb_sr_enter);
        IupSetCallback(sr_list, "K_ESC", (Icallback)cb_sr_esc);
        Ihandle *box = IupVbox(qrow, sr_count, sr_list, NULL);
        IupSetAttribute(box, "MARGIN", "8x8");
        IupSetAttribute(box, "GAP", "4");
        sr_dlg = IupDialog(box);
        IupSetAttribute(sr_dlg, "TITLE", "Search messages");
        IupSetAttribute(sr_dlg, "RASTERSIZE", rsz("520x400"));
        IupSetAttribute(sr_dlg, "MINBOX", "NO");
        IupSetAttribute(sr_dlg, "MAXBOX", "NO");
        IupSetAttributeHandle(sr_dlg, "PARENTDIALOG", dlg);
        IupSetCallback(sr_dlg, "K_ESC", (Icallback)cb_sr_esc);
    }
    IupShowXY(sr_dlg, IUP_CENTER, IUP_CENTER);
    IupSetFocus(sr_input);
    return IUP_DEFAULT;
}

static Ihandle *build_menu(void) {
    Ihandle *acct = IupSubmenu("Account", IupMenu(
        mk("Add account...", (Icallback)cb_menu_add),
        mk("Manage accounts...", (Icallback)cb_menu_accounts),
        IupSeparator(), mk("Quit", (Icallback)cb_menu_quit), NULL));
    Ihandle *act = IupSubmenu("Actions", IupMenu(
        mk("Join channel / room...", (Icallback)cb_menu_join),
        mk("Message user (DM)...", (Icallback)cb_menu_dm),
        mk("Send file / image...", (Icallback)cb_menu_sendfile),
        mk("Soundboard: play WAV...", (Icallback)cb_menu_play),
        IupSeparator(), mk("Image settings...", (Icallback)cb_menu_imgopts),
        mk("Audio settings...", (Icallback)cb_menu_audio), NULL));
    Ihandle *view = IupSubmenu("View", IupMenu(
        mk("Error log", (Icallback)cb_menu_errors),
        mk("Debug console", (Icallback)cb_menu_debug), NULL));
    Ihandle *help = IupSubmenu("Help", IupMenu(mk("About...", (Icallback)cb_about), NULL));
    return IupMenu(acct, act, view, help, NULL);
}

static void make_images(void) {
    if (load_theme_icon("avatar-default", 16, "TRI_IMG_ACCT") != 0 &&
        load_theme_icon("system-users",  16, "TRI_IMG_ACCT") != 0) {
        unsigned char acct[16 * 16];
        for (int y = 0; y < 16; y++) for (int x = 0; x < 16; x++) {
            int hx = x - 8, hy = y - 5, head = hx * hx + hy * hy <= 9;
            int sx = x - 8, sy = y - 18, sd = sx * sx + sy * sy, shoulder = y >= 9 && sd <= 100 && sd >= 49;
            acct[y * 16 + x] = (head || shoulder) ? 1 : 0;
        }
        Ihandle *ai = IupImage(16, 16, acct);
        IupSetAttribute(ai, "0", "BGCOLOR"); IupSetAttribute(ai, "1", "58 104 168");
        IupSetHandle("TRI_IMG_ACCT", ai);
    }
    if (load_theme_icon("folder", 16, "TRI_IMG_FOLDER") != 0) {
        unsigned char fold[16 * 16];
        for (int y = 0; y < 16; y++) for (int x = 0; x < 16; x++) {
            int body = y >= 5 && y <= 13 && x >= 2 && x <= 13;
            int tab  = y >= 3 && y <= 5 && x >= 2 && x <= 7;
            fold[y * 16 + x] = (body || tab) ? 1 : 0;
        }
        Ihandle *fi = IupImage(16, 16, fold);
        IupSetAttribute(fi, "0", "BGCOLOR"); IupSetAttribute(fi, "1", "222 176 70");
        IupSetHandle("TRI_IMG_FOLDER", fi);
    }

    load_theme_icon("user-available", 16, "TRI_IMG_CHAN");
    (void)(load_theme_icon("mail-unread",    16, "TRI_IMG_INBOX")   == 0 || load_theme_icon("mail-message-new", 16, "TRI_IMG_INBOX"));
    (void)(load_theme_icon("emblem-favorite",16, "TRI_IMG_SAVED")   == 0 || load_theme_icon("bookmark-new",     16, "TRI_IMG_SAVED"));
}

int main(int argc, char **argv) {
    IupOpen(&argc, &argv);
    ui_theme_init();

    { GtkSettings *gs = gtk_settings_get_default(); if (gs) g_object_set(gs, "gtk-button-images", TRUE, NULL); }
    make_images();
    media_dir_init();
    if (opt_purge) media_purge();

    core = tri_core_new(on_event, NULL);
    if (!core) { fprintf(stderr, "trichat: %s\n", tri_last_error()); return 1; }

    tree = IupTree();
    IupSetAttribute(tree, "RASTERSIZE", rsz("200x"));
    IupSetAttribute(tree, "TITLE", "Accounts");
    IupSetCallback(tree, "SELECTION_CB", (Icallback)cb_treeselect);
    IupSetCallback(tree, "EXECUTELEAF_CB", (Icallback)cb_treeexec);
    IupSetCallback(tree, "BUTTON_CB", (Icallback)cb_tree_button);
    IupSetAttribute(tree, "SHOWDRAGDROP", "YES");
    IupSetCallback(tree, "DRAGDROP_CB", (Icallback)cb_dragdrop);

    tabs = IupTabs(NULL);
    IupSetAttribute(tabs, "EXPAND", "YES");
    IupSetAttribute(tabs, "SHOWCLOSE", "YES");
    IupSetCallback(tabs, "TABCHANGE_CB", (Icallback)cb_tabchange);
    IupSetCallback(tabs, "TABCLOSE_CB", (Icallback)cb_tabclose);

    input = IupText(NULL);
    IupSetAttribute(input, "EXPAND", "HORIZONTAL");
    IupSetCallback(input, "K_CR", (Icallback)cb_send);
    IupSetCallback(input, "VALUECHANGED_CB", (Icallback)cb_input_changed);
    IupSetCallback(input, "K_cV", (Icallback)cb_input_paste);
    IupSetCallback(input, "K_TAB", (Icallback)cb_input_tab);
    IupSetAttribute(input, "DROPFILESTARGET", "YES");
    IupSetCallback(input, "DROPFILES_CB", (Icallback)cb_input_dropfiles);

    if (load_theme_icon("mail-attachment", 16, "trichat_attach") == 0) {
        attach = IupButton(NULL, NULL);
        IupSetAttribute(attach, "IMAGE", "trichat_attach");
    } else {
        attach = IupButton("Attach", NULL);
    }
    IupSetAttribute(attach, "TIP", "Attach a file / image");
    IupSetCallback(attach, "ACTION", (Icallback)cb_menu_sendfile);

    omemo_toggle = IupToggle("OMEMO", NULL);
    IupSetCallback(omemo_toggle, "ACTION", (Icallback)cb_omemo_toggle);
    IupSetAttribute(omemo_toggle, "TIP", "Encrypt this conversation with OMEMO");
    IupSetAttribute(omemo_toggle, "ACTIVE", "NO");
    Ihandle *inputrow = IupHbox(attach, omemo_toggle, input, NULL);
    IupSetAttribute(inputrow, "ALIGNMENT", "ACENTER");

    attachbar = IupHbox(NULL);
    IupSetAttribute(attachbar, "GAP", "3");
    IupSetAttribute(attachbar, "ALIGNMENT", "ACENTER");
    attachscroll = IupScrollBox(attachbar);
    IupSetAttribute(attachscroll, "EXPAND", "HORIZONTAL");
    IupSetAttribute(attachscroll, "RASTERSIZE", "x1");
    attach_clear = IupButton("Clear", NULL);
    IupSetCallback(attach_clear, "ACTION", (Icallback)cb_attach_clear);
    IupSetAttribute(attach_clear, "ACTIVE", "NO");
    IupSetAttribute(attach_clear, "FLOATING", "YES");
    IupSetAttribute(attach_clear, "VISIBLE", "NO");
    attachrow = IupHbox(attachscroll, attach_clear, NULL);
    IupSetAttribute(attachrow, "ALIGNMENT", "ACENTER");
    IupSetAttribute(attachrow, "GAP", "4");

    members = IupList(NULL);
    IupSetAttribute(members, "EXPAND", "VERTICAL");
    IupSetAttribute(members, "RASTERSIZE", rsz("150x120"));
    IupSetCallback(members, "DBLCLICK_CB", (Icallback)cb_members_dblclick);
    IupSetCallback(members, "BUTTON_CB", (Icallback)cb_members_button);
    mempanel = IupVbox(IupLabel("Members"), members, NULL);
    IupSetAttribute(mempanel, "GAP", "2");
    IupSetAttribute(mempanel, "EXPAND", "VERTICAL");

    Ihandle *chatarea = IupHbox(tabs, mempanel, NULL);
    IupSetAttribute(chatarea, "GAP", "4");

    hdr_title = IupLabel("");
    IupSetAttribute(hdr_title, "FONTSTYLE", "Bold");
    IupSetAttribute(hdr_title, "EXPAND", "HORIZONTAL");
    hdr_status = IupLabel("");
    top_call_btn  = IupButton("Call", NULL);
    IupSetCallback(top_call_btn, "ACTION", (Icallback)cb_topcall);
    IupSetAttribute(top_call_btn, "TIP", "Start a voice call with this contact");
    top_video_btn = IupButton("Video", NULL);
    IupSetCallback(top_video_btn, "ACTION", (Icallback)cb_topvideo);
    IupSetAttribute(top_video_btn, "TIP", "Start a video call with this contact");
    Ihandle *topbar = IupHbox(hdr_title, hdr_status, top_call_btn, top_video_btn, NULL);
    IupSetAttribute(topbar, "GAP", "8");
    IupSetAttribute(topbar, "ALIGNMENT", "ACENTER");
    IupSetAttribute(topbar, "NMARGIN", "4x2");

    typing_lbl = IupLabel("");
    IupSetAttribute(typing_lbl, "EXPAND", "HORIZONTAL");
    IupSetAttribute(typing_lbl, "FGCOLOR", "128 128 128");

    reply_preview = IupLabel("");
    IupSetAttribute(reply_preview, "EXPAND", "HORIZONTAL");
    IupSetAttribute(reply_preview, "FGCOLOR", "96 96 96");
    Ihandle *reply_x = IupButton("\xC3\x97", NULL);
    IupSetAttribute(reply_x, "PADDING", "4x0");
    IupSetStrAttribute(reply_x, "TIP", "Cancel reply");
    IupSetCallback(reply_x, "ACTION", (Icallback)cb_reply_cancel);
    replybar = IupHbox(reply_preview, reply_x, NULL);
    IupSetAttribute(replybar, "ALIGNMENT", "ACENTER");
    IupSetAttribute(replybar, "GAP", "4");
    IupSetAttribute(replybar, "FLOATING", "YES");
    IupSetAttribute(replybar, "VISIBLE", "NO");

    Ihandle *right = IupVbox(topbar, chatarea, attachrow, typing_lbl, replybar, inputrow, NULL);

    IupSetAttribute(right, "GAP", "12");

    Ihandle *search_btn = IupButton("Search messages...", NULL);
    IupSetCallback(search_btn, "ACTION", (Icallback)cb_search_open);
    IupSetAttribute(search_btn, "EXPAND", "HORIZONTAL");
    Ihandle *navcol = IupVbox(tree, search_btn, NULL);
    IupSetAttribute(navcol, "GAP", "4");
    Ihandle *split = IupSplit(navcol, right);
    IupSetAttribute(split, "VALUE", "250");

    dlg = IupDialog(split);
    IupSetAttribute(dlg, "TITLE", "Trichat");
    IupSetAttribute(dlg, "RASTERSIZE", rsz("820x560"));
    IupSetCallback(dlg, "K_cW", (Icallback)cb_key_closetab);
    IupSetCallback(dlg, "K_cK", (Icallback)cb_key_quickswitch);
    IupSetAttributeHandle(dlg, "MENU", build_menu());

    Ihandle *timer = IupTimer();
    IupSetAttribute(timer, "TIME", "20");
    IupSetCallback(timer, "ACTION_CB", (Icallback)cb_timer);
    IupSetAttribute(timer, "RUN", "YES");

    IupShowXY(dlg, IUP_CENTER, IUP_CENTER);

    if (getenv("TRICHAT_GEOM")) {
        Ihandle *gt = IupTimer();
        IupSetAttribute(gt, "TIME", "1000");
        IupSetCallback(gt, "ACTION_CB", (Icallback)cb_geom_timer);
        IupSetAttribute(gt, "RUN", "YES");
    }

    if (getenv("TRICHAT_SELFTEST")) {
        account_t *a = tri_connect(core, "echo", "selftest", NULL);
        if (a) tri_join(a, "#smoke");
        if (!a || !view_find("echo:selftest", "#smoke"))
            { fprintf(stderr, "selftest: event path did not build a view\n"); return 2; }

        tri_folder_t *f = tri_folder_create(core, "box", NULL);
        tri_folder_t *sub = tri_folder_create(core, "sub", f);
        if (!f || !sub) { fprintf(stderr, "selftest: folder not created\n"); return 2; }
        tri_account_move_to_folder(a, f);
        tri_folder_ref_add(f, "echo:selftest", "#smoke");
        rebuild_tree();
        if (tri_root_item_count(core) != 1)
            { fprintf(stderr, "selftest: account did not move into folder\n"); return 2; }
        if (tri_folder_item_count(f) != 3)
            { fprintf(stderr, "selftest: folder contents wrong\n"); return 2; }
        if (tri_folder_ref_count_for("echo:selftest", "#smoke") != 1)
            { fprintf(stderr, "selftest: channel reference not recorded\n"); return 2; }

        view_t *sv = view_find("echo:selftest", "#smoke");
        if (sv) { view_add(sv, VIT_MSG, "alice", "hi http://example.com there", 0);
                  view_add(sv, VIT_STATUS, NULL, "bob joined #smoke", 0);
                  if (sv->nit < 2) { fprintf(stderr, "selftest: scrollback did not record items\n"); return 2; } }

        if (sv) {
            sv->a_item = 0; sv->a_off = 0; sv->c_item = sv->nit - 1;
            char cl[256]; sv->c_off = item_canon(sv, sv->nit - 1, cl, sizeof cl); sv->sel_on = 1;
            char *got = build_selection(sv);
            if (!got || !strstr(got, "alice") || !strstr(got, "example.com"))
                { fprintf(stderr, "selftest: selection copy did not round-trip the line\n"); free(got); return 2; }
            free(got); sv->sel_on = 0;
        }

        if (sv) {
            int before = sv->nit;
            tri_user_set_ignored(a, "spammer", 1);
            tri_event_t mev = { TRI_EV_MESSAGE, "echo:selftest", "#smoke", "flood", "spammer", 0 };
            on_event(NULL, &mev);
            if (sv->nit != before) { fprintf(stderr, "selftest: ignored user's message was not filtered\n"); return 2; }
            tri_user_set_ignored(a, "spammer", 0);
            on_event(NULL, &mev);
            if (sv->nit != before + 1) { fprintf(stderr, "selftest: un-ignored message did not appear\n"); return 2; }
        }

        if (sv) {
            int before = sv->nit;
            tri_event_t tv = { TRI_EV_TYPING, "echo:selftest", "#smoke", "composing", "alice", 0 };
            on_event(NULL, &tv);
            if (sv->nit != before) { fprintf(stderr, "selftest: typing event must not add scrollback\n"); return 2; }
            if (strcmp(sv->typing_nick, "alice")) { fprintf(stderr, "selftest: typing indicator not set\n"); return 2; }
            tri_event_t amsg = { TRI_EV_MESSAGE, "echo:selftest", "#smoke", "hello", "alice", 0 };
            on_event(NULL, &amsg);
            if (sv->typing_nick[0]) { fprintf(stderr, "selftest: message did not clear typing indicator\n"); return 2; }
            tri_user_set_ignored(a, "alice", 1);
            on_event(NULL, &tv);
            if (sv->typing_nick[0]) { fprintf(stderr, "selftest: muted user's typing was not dropped\n"); return 2; }
            tri_user_set_ignored(a, "alice", 0);
        }

        open_special(ERRORS_KEY, "Error log");
        view_t *ev_v = view_find(ERRORS_KEY, "");
        if (!ev_v || !ev_v->tab) { fprintf(stderr, "selftest: error-log view did not open\n"); return 2; }
        close_tab(ev_v);
        ev_v = view_find(ERRORS_KEY, "");
        if (!ev_v || ev_v->tab) { fprintf(stderr, "selftest: close_tab should keep the view but drop its tab\n"); return 2; }
        drop_view(ev_v);
        if (view_find(ERRORS_KEY, "")) { fprintf(stderr, "selftest: drop_view did not remove the view\n"); return 2; }

        for (int k = 0; k < nnodemap; k++) {
            int p = IupGetIntId(tree, "PARENT", nodemap[k].node);
            if (p != nodemap[k].parent)
                { fprintf(stderr, "selftest: node %d parent %d != expected %d\n", nodemap[k].node, p, nodemap[k].parent); return 2; }
        }

        if (sv) {
            int node = -1;
            for (int k = 0; k < nnodemap; k++) if (nodemap[k].v == sv && nodemap[k].kind == NODE_CHANNEL) { node = nodemap[k].node; break; }
            sv->unread = 1; color_view_nodes(sv);
            if (node < 0 || strcmp(IupGetAttributeId(tree, "COLOR", node), "110 150 235"))
                { fprintf(stderr, "selftest: unread node not tinted\n"); return 2; }
            mark_read(sv);
            if (sv->unread != 0 || strcmp(IupGetAttributeId(tree, "COLOR", node), tree_default_fg()))
                { fprintf(stderr, "selftest: mark_read did not revert node COLOR (got '%s')\n", IupGetAttributeId(tree, "COLOR", node)); return 2; }
        }
        if (sv) switch_to(sv);

        if (sv && sv->tab) {
            view_add(sv, VIT_MSG, "carol", "the quick brown fox jumps over the lazy dog again and again", 0);
            relayout(sv, sv->tab, 380);
            long m0 = g_textmeasures;
            relayout(sv, sv->tab, 380);
            if (g_textmeasures != m0)
                { fprintf(stderr, "selftest: text not cached across layouts (%ld re-measures) - scroll would lag\n", g_textmeasures - m0); return 2; }
        }

        if (sv) {
            view_t *sv2 = view_get("echo:selftest", "#other");
            GdkPixbuf *tp = gdk_pixbuf_new(GDK_COLORSPACE_RGB, TRUE, 8, 200, 120);
            char png[600]; snprintf(png, sizeof png, "%s/qtest.png", g_mediadir);
            if (tp) { gdk_pixbuf_fill(tp, 0xff0000ffu); gdk_pixbuf_save(tp, png, "png", NULL, NULL); g_object_unref(tp); }
            switch_to(sv); queue_add(png); queue_add("/tmp/not-an-image.txt");
            if (sv->nattach != 2) { fprintf(stderr, "selftest: queue add failed\n"); return 2; }
            switch_to(sv2);
            if (sv2->nattach != 0) { fprintf(stderr, "selftest: attachment queue leaked across channels\n"); return 2; }
            queue_add("/tmp/other.bin");
            switch_to(sv);
            if (sv->nattach != 2 || sv2->nattach != 1) { fprintf(stderr, "selftest: per-channel queues not independent\n"); return 2; }
            int imgs = 0; for (int k = 0; k < g_nqc; k++) if (g_qc[k].img) imgs++;
            if (imgs != 1) { fprintf(stderr, "selftest: image thumbnail did not decode (imgs=%d)\n", imgs); return 2; }

            long d0 = g_thumb_decodes; attachbar_refresh();
            if (g_thumb_decodes != d0) { fprintf(stderr, "selftest: thumbnail re-decoded on rebuild (paste-lag regression)\n"); return 2; }
            Ihandle *cell0 = IupGetChild(attachbar, 0);
            Ihandle *thumb0 = IupGetChild(cell0, 0);
            int th_h = thumb0 ? IupGetInt(thumb0, "RASTERSIZE") : 0;
            if (thumb0 && IupGetInt2(thumb0, "RASTERSIZE") < 8)
                { fprintf(stderr, "selftest: thumbnail label has no size (%s)\n", IupGetAttribute(thumb0, "RASTERSIZE")); return 2; }
            (void)th_h;
            cb_qthumb_click(IupGetChild(cell0, 1));
            if (sv->nattach != 1) { fprintf(stderr, "selftest: attachment remove failed\n"); return 2; }
            cb_attach_clear(NULL);
            if (sv->nattach != 0) { fprintf(stderr, "selftest: attachment clear failed\n"); return 2; }

            for (int q = 0; q < 20; q++) queue_add(png);
            int strip_w = IupGetInt(attachbar, "RASTERSIZE");
            int box_w = IupGetInt(attachscroll, "RASTERSIZE");
            if (strip_w <= box_w) { fprintf(stderr, "selftest: attachment strip is not scrolling (no overflow)\n"); return 2; }
            if (box_w > IupGetInt(dlg, "RASTERSIZE")) { fprintf(stderr, "selftest: attachment scrollbox exceeds the dialog width\n"); return 2; }
            cb_attach_clear(NULL);
            unlink(png);
        }

        if (sv && a) {
            view_t *save_v = saved_view();
            int sbefore = save_v->nit;
            tri_saved_add(core, "echo:selftest", "#smoke", "carol", "first pin", 111);
            saved_view_add("echo:selftest", "#smoke", "carol", "first pin", 111);
            tri_saved_add(core, "echo:selftest", "#other", "dave", "second pin", 222);
            saved_view_add("echo:selftest", "#other", "dave", "second pin", 222);
            if (tri_saved_count(core) != 2) { fprintf(stderr, "selftest: saved add count wrong\n"); return 2; }
            if (save_v->nit != sbefore + 2) { fprintf(stderr, "selftest: saved view not appended\n"); return 2; }
            const char *ak, *tg, *nk, *tx; long long ts;
            tri_saved_remove(core, 0);
            if (tri_saved_count(core) != 1 || !tri_saved_get(core, 0, &ak, &tg, &nk, &tx, &ts) || strcmp(tx, "second pin"))
                { fprintf(stderr, "selftest: saved remove did not preserve order\n"); return 2; }
            tri_saved_remove(core, 0);

            tri_channel_set_notify(a, "#smoke", TRI_NOTIFY_MUTE);
            if (tri_channel_notify(a, "#smoke") != TRI_NOTIFY_MUTE) { fprintf(stderr, "selftest: notify set/get failed\n"); return 2; }
            tri_channel_set_notify(a, "#smoke", 99);
            if (tri_channel_notify(a, "#smoke") != TRI_NOTIFY_MUTE) { fprintf(stderr, "selftest: notify high clamp failed\n"); return 2; }
            tri_channel_set_notify(a, "#smoke", -5);
            if (tri_channel_notify(a, "#smoke") != TRI_NOTIFY_ALL) { fprintf(stderr, "selftest: notify low clamp failed\n"); return 2; }

            view_t *mv = view_get("echo:selftest", "#muted"); tri_channel_set_notify(a, "#muted", TRI_NOTIFY_MUTE);
            view_t *lv = view_get("echo:selftest", "#loud");  tri_channel_set_notify(a, "#loud", TRI_NOTIFY_ALL);
            switch_to(sv); mv->unread = 0; lv->unread = 0;
            tri_event_t mmsg = { TRI_EV_MESSAGE, "echo:selftest", "#muted", "hi there", "erin", 0 }; on_event(NULL, &mmsg);
            tri_event_t lmsg = { TRI_EV_MESSAGE, "echo:selftest", "#loud",  "hi there", "erin", 0 }; on_event(NULL, &lmsg);
            if (mv->unread != 0) { fprintf(stderr, "selftest: muted channel got an unread tint\n"); return 2; }
            if (lv->unread != 1) { fprintf(stderr, "selftest: normal channel did not tint\n"); return 2; }

            quickswitch_open();
            qs_populate("smoke"); if (qs_nrows < 1) { fprintf(stderr, "selftest: quick switcher missed 'smoke'\n"); return 2; }
            qs_populate("zzz-nope"); if (qs_nrows != 0) { fprintf(stderr, "selftest: quick switcher matched nothing-filter\n"); return 2; }
            qs_populate("");
            for (int k = 0; k < qs_nrows; k++) if (qs_rows[k]->acct[0] == '*') { fprintf(stderr, "selftest: quick switcher listed a pseudo-view\n"); return 2; }
            IupHide(qs_dlg);

            view_add(sv, VIT_MSG, "carol", "xyzzy-unique-token here", 0);
            cb_search_open(NULL);
            IupSetStrAttribute(sr_input, "VALUE", "xyzzy-unique-token");
            sr_run(NULL);
            if (sr_nrows < 1) { fprintf(stderr, "selftest: search did not find its token\n"); return 2; }
            sv->seek_to = 0; sr_choose(1);
            if (sv->seek_to == 0) { fprintf(stderr, "selftest: search jump did not arm a seek\n"); return 2; }
            IupHide(sr_dlg);

            tri_event_t cin = { TRI_EV_CALL, "echo:selftest", "peer@host", "incoming", "audio", 0, 0 };
            call_on_event(&cin);
            if (g_call.st != CALL_INCOMING || !g_call.shown) { fprintf(stderr, "selftest: incoming call did not open the call UI\n"); return 2; }
            tri_event_t cend = { TRI_EV_CALL, "echo:selftest", "peer@host", "ended", NULL, 0, 0 };
            call_on_event(&cend);
            if (g_call.st != CALL_NONE || g_call.shown) { fprintf(stderr, "selftest: ended call did not close the call UI\n"); return 2; }

            switch_to(sv); IupSetStrAttribute(input, "VALUE", "half-typed for smoke");
            view_t *dv2 = view_get("echo:selftest", "#draft2");
            view_became_current(dv2);
            if (strcmp(sv->draft, "half-typed for smoke")) { fprintf(stderr, "selftest: draft not stashed on leave\n"); return 2; }
            if (IupGetAttribute(input, "VALUE")[0]) { fprintf(stderr, "selftest: draft not cleared on entering empty view\n"); return 2; }
            IupSetStrAttribute(input, "VALUE", "half-typed for draft2");
            view_became_current(sv);
            if (strcmp(IupGetAttribute(input, "VALUE"), "half-typed for smoke")) { fprintf(stderr, "selftest: smoke draft not restored\n"); return 2; }
            if (strcmp(dv2->draft, "half-typed for draft2")) { fprintf(stderr, "selftest: draft2 not stashed\n"); return 2; }

            tri_roster_upsert(a, "#smoke", "alice_bot", 0);
            switch_to(sv); IupSetStrAttribute(input, "VALUE", "al"); IupSetInt(input, "CARETPOS", 2);
            cb_input_tab(input);
            if (strncmp(IupGetAttribute(input, "VALUE"), "alice_bot", 9)) { fprintf(stderr, "selftest: tab-complete failed (got '%s')\n", IupGetAttribute(input, "VALUE")); return 2; }
            IupSetStrAttribute(input, "VALUE", "");
        }
        geom_dump();
        const char *url = getenv("TRICHAT_SELFTEST_IRC");
        if (url) { const char *b = backend_for_url(url); if (b) tri_connect(core, b, "live", url); }
        Ihandle *q = IupTimer();
        IupSetAttribute(q, "TIME", url ? "10000" : "800");
        IupSetCallback(q, "ACTION_CB", (Icallback)cb_menu_quit);
        IupSetAttribute(q, "RUN", "YES");
    } else {
        tri_core_set_store(core, tri_default_store_path());
        tri_accounts_load(core);
    }

    saved_view_load();
    rebuild_tree();
    IupMainLoop();
    core_alive = 0;
    if (opt_purge) media_purge();
    tri_core_free(core);
    IupClose();
    return 0;
}
