# Dev shell.
#   CLI:  nix-shell               then make trichat / make check
#   GUI:  nix-shell --arg withGui true   then make trichat-gui
{ pkgs ? import <nixpkgs> {}, withGui ? true }:

pkgs.mkShell {
  name = "trichat-dev";

  buildInputs = with pkgs; [
    gcc
    gnumake
    pkg-config
    autoconf
    automake
    libtool
    perl
    libpulseaudio
    ffmpeg
    xorg.libX11
    xorg.libXext
  ] ++ pkgs.lib.optionals withGui [
    gtk3
    gdk-pixbuf
    xorg.libXmu
    xorg.libXt
  ];
}
