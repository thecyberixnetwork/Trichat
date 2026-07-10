CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -Os
CFLAGS  += -Wno-format-truncation -Wno-missing-field-initializers -Wno-misleading-indentation -Wno-cast-function-type -Wno-deprecated-declarations
HARDEN         = -flto=auto -fvisibility=hidden -fno-ident -ffunction-sections -fdata-sections
HARDEN_LDFLAGS = -s -Wl,--gc-sections -Wl,--build-id=none
BACKENDS = src/core.c src/http.c src/resolve.c src/backend_echo.c src/backend_irc.c src/backend_mumble.c src/backend_xmpp.c src/jingle.c src/stun.c src/ice.c src/dtls.c src/srtp.c src/rtpvp8.c src/ivf.c src/rtph264.c src/vdecode.c
OMEMO_SRC = src/omemo.c src/omemo_xeddsa.c src/omemo_wire.c src/omemo_session.c src/omemo_envelope.c src/omemo_store.c

WOLF     = wolfssl-5.9.2/wolfssl-5.9.2
WOLF_LIB = $(WOLF)/src/.libs/libwolfssl.a
WOLF_ABI = -DHAVE_ANONYMOUS_INLINE_AGGREGATES
OPUS     = opus-1.6.1
OPUS_LIB = $(OPUS)/.libs/libopus.a

ifeq ($(shell pkg-config --exists libpulse-simple && echo yes),yes)
PULSE_CFLAGS = -DTRI_PULSE $(shell pkg-config --cflags libpulse-simple)
PULSE_LIBS   = $(shell pkg-config --libs libpulse-simple)
endif

ifeq ($(shell pkg-config --exists x11 xext && echo yes),yes)
X11_CFLAGS = -DTRI_X11 $(shell pkg-config --cflags x11 xext)
X11_LIBS   = $(shell pkg-config --libs x11 xext)
X11_SRC    = src/x11cap.c
endif

ifeq ($(shell pkg-config --exists libavcodec libavutil libswscale && echo yes),yes)
AVCODEC_CFLAGS = -DTRI_AVCODEC $(shell pkg-config --cflags libavcodec libavutil libswscale)
AVCODEC_LIBS   = $(shell pkg-config --libs libavcodec libavutil libswscale)
endif

ifneq ($(MUJI_MESH),0)
MUJI_CFLAGS = -DTRI_MUJI_MESH
endif

DEP_CFLAGS = -DTRI_TLS -D_GNU_SOURCE $(WOLF_ABI) -I$(WOLF) -I$(OPUS)/include $(PULSE_CFLAGS) $(X11_CFLAGS) $(AVCODEC_CFLAGS) $(MUJI_CFLAGS)
DEP_LIBS   = $(WOLF_LIB) $(OPUS_LIB) $(PULSE_LIBS) $(X11_LIBS) $(AVCODEC_LIBS) -lpthread -lm
BACKENDS  += $(X11_SRC)

trichat: $(BACKENDS) $(OMEMO_SRC) src/cli.c src/trichat.h src/omemo.h $(WOLF_LIB) $(OPUS_LIB)
	umask 0 && $(CC) $(CFLAGS) $(HARDEN) $(DEP_CFLAGS) -o $@ $(BACKENDS) $(OMEMO_SRC) src/cli.c $(DEP_LIBS) $(HARDEN_LDFLAGS)

IUP      = iup-3.32_Linux313_64_lib(1)
PIXBUF_CFLAGS = $(shell pkg-config --cflags gtk+-3.0 gdk-pixbuf-2.0 2>/dev/null)
PIXBUF_LIBS   = $(shell pkg-config --libs gdk-pixbuf-2.0 2>/dev/null)
trichat-gui: $(BACKENDS) $(OMEMO_SRC) src/gui.c src/trichat.h src/omemo.h $(WOLF_LIB) $(OPUS_LIB)
	umask 0 && $(CC) $(CFLAGS) $(HARDEN) $(DEP_CFLAGS) $(PIXBUF_CFLAGS) -I'$(IUP)/include' -o $@ $(BACKENDS) $(OMEMO_SRC) src/gui.c \
		-L'$(IUP)' -Wl,-rpath,'$(IUP)' -liup $(DEP_LIBS) $(shell pkg-config --libs gtk+-3.0 x11 xt xext 2>/dev/null) $(PIXBUF_LIBS) $(HARDEN_LDFLAGS)

$(WOLF_LIB):
	cd $(WOLF) && ./configure --enable-static --disable-shared --enable-tls13 --enable-sni \
		--enable-curve25519 --enable-ed25519 --enable-dtls --enable-srtp \
		--enable-certgen --enable-keygen --enable-opensslextra CFLAGS="-Os -fPIC" && $(MAKE)

$(OPUS_LIB):
	cd $(OPUS) && ./configure --enable-static --disable-shared --disable-doc --disable-extra-programs CFLAGS="-Os -fPIC" && \
		$(MAKE) AUTOMAKE=true ACLOCAL=true AUTOCONF=true AUTOHEADER=true

check: trichat
	@printf 'connect echo alice\njoin alice #x\nsend alice #x hello-world\nquit\n' \
		| ./trichat | tee /dev/stderr | grep -q '<< \[echo:alice/#x\] hello-world' \
		&& echo "PASS: round-trip through event loop" \
		|| { echo "FAIL: no echo round-trip"; exit 1; }

gui-check: trichat-gui
	@TRICHAT_SELFTEST=1 ./trichat-gui && echo "PASS: GUI mapped and exited cleanly" \
		|| { echo "FAIL: GUI crashed on startup"; exit 1; }

omemo-check: $(OMEMO_SRC) src/omemo_test.c src/omemo.h $(WOLF_LIB)
	$(CC) $(CFLAGS) -DTRI_TLS $(WOLF_ABI) -I$(WOLF) -o trichat-omemo-check $(OMEMO_SRC) src/omemo_test.c $(WOLF_LIB) -lpthread -lm
	@./trichat-omemo-check

persist-check: $(BACKENDS) $(OMEMO_SRC) src/persist_test.c src/trichat.h $(WOLF_LIB) $(OPUS_LIB)
	$(CC) $(CFLAGS) $(DEP_CFLAGS) -o trichat-persist-check $(BACKENDS) $(OMEMO_SRC) src/persist_test.c $(DEP_LIBS)
	@./trichat-persist-check

jingle-check: src/jingle.c src/jingle_test.c src/jingle.h
	$(CC) $(CFLAGS) -o trichat-jingle-check src/jingle.c src/jingle_test.c
	@./trichat-jingle-check

stun-check: src/stun.c src/stun_test.c src/stun.h $(WOLF_LIB)
	$(CC) $(CFLAGS) -DTRI_TLS $(WOLF_ABI) -I$(WOLF) -o trichat-stun-check src/stun.c src/stun_test.c $(WOLF_LIB) -lpthread -lm
	@./trichat-stun-check

ice-check: src/ice.c src/stun.c src/ice_test.c src/ice.h src/stun.h $(WOLF_LIB)
	$(CC) $(CFLAGS) -DTRI_TLS -D_GNU_SOURCE $(WOLF_ABI) -I$(WOLF) -o trichat-ice-check src/ice.c src/stun.c src/ice_test.c $(WOLF_LIB) -lpthread -lm
	@./trichat-ice-check

dtls-check: src/dtls.c src/dtls_test.c src/dtls.h $(WOLF_LIB)
	$(CC) $(CFLAGS) -DTRI_TLS -D_GNU_SOURCE $(WOLF_ABI) -I$(WOLF) -o trichat-dtls-check src/dtls.c src/dtls_test.c $(WOLF_LIB) -lpthread -lm
	@./trichat-dtls-check

srtp-check: src/srtp.c src/srtp_test.c src/srtp.h $(WOLF_LIB)
	$(CC) $(CFLAGS) -DTRI_TLS $(WOLF_ABI) -I$(WOLF) -o trichat-srtp-check src/srtp.c src/srtp_test.c $(WOLF_LIB) -lpthread -lm
	@./trichat-srtp-check

vp8-check: src/rtpvp8.c src/rtpvp8_test.c src/rtpvp8.h
	$(CC) $(CFLAGS) -o trichat-vp8-check src/rtpvp8.c src/rtpvp8_test.c
	@./trichat-vp8-check

ivf-check: src/ivf.c src/ivf_test.c src/ivf.h src/rtpvp8.h
	$(CC) $(CFLAGS) -o trichat-ivf-check src/ivf.c src/ivf_test.c
	@./trichat-ivf-check

h264-check: src/rtph264.c src/rtph264_test.c src/rtph264.h
	$(CC) $(CFLAGS) -o trichat-h264-check src/rtph264.c src/rtph264_test.c
	@./trichat-h264-check

clean:
	rm -f trichat trichat-gui trichat-omemo-check trichat-persist-check trichat-jingle-check trichat-stun-check trichat-ice-check trichat-srtp-check trichat-dtls-check trichat-vp8-check trichat-ivf-check trichat-h264-check

.PHONY: check gui-check omemo-check persist-check jingle-check stun-check ice-check srtp-check dtls-check vp8-check ivf-check h264-check clean
