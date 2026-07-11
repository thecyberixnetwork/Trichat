# Trichat
A trinity protocol chat client &amp; reusable library that implements and combines IRC, XMPP, and Mumble into a cohesive, unified communication suite written in pure C.

Goal: Obsolete all other IRC/XMPP/Mumble clients by Binding XMPP, IRC, and Mumble protocols together inside of one lightweight cross-platform native toolkit program cleanly with all relevant features of each protocol available to the end-user in a UX-friendly manner

# warning: I do not know what I am doing, but I use Trichat personally
If something does not work for you, it likely does not work for me, and I am either unaware of it or I just haven't fixed it yet (or it was intentional)

# Support Trichat and The Cyberix Network
Trichat is a product of the Cyberix network. I deeply appreciate donations and support in exchange for making the source code public. 

I only need as much as 14$ per month to keep things running.
https://cy-x.net/bbs/donate

# DEVELOPMENT
Work is done primarily within Cyberix's chatrooms.

## IRC:
cy-x.net
## XMPP:
xmpp://hyperborea@chat.cy-x.net
## MUMBLE:
cy-x.net
## SSH CHAT:
cy-x.net
## CYBERIX WEBCHAT:
https://cy-x.net/bbs/webchat

All communication channels are bridged.

# how 2 build

The wolfSSL and libopus static libs are built from the vendored trees on the
first make which is slow but one-time if cached

```sh
make trichat
make trichat-gui
make check 
```

## GUI

The GUI links GTK 3 (will fix soon) and gdk-pixbuf so it needs dev headers and
`pkg-config`. On NixOS, the bundled `shell.nix` provides everything so just do:

```sh
nix-shell --run 'make trichat-gui'
```

Without nix you will have to install `pkg-config`, `gtk+-3.0` and `gdk-pixbuf-2.0` dev packages
manually before you `make trichat-gui`

Optional features that are in here that will only work when their libs are present:
`-DTRI_PULSE` aka (PulseAudio which will fall back to a subprocess player otherwise)
`-DTRI_AVCODEC` (video decoding)
`-DTRI_X11` (screen capture)
