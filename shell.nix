{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz";
  }) { },
}:
let
  requiredPkgs = with pkgs; [
    bison
    cargo
    cmake
    flex
    git
    pkg-config
    rustc
    zlib
  ];
in
pkgs.mkShell {
  name = "fugue-shell";
  buildInputs = requiredPkgs;
  shellHook = ''
    export RUST_BACKTRACE=1
  '';
}
