{
  description = "Fugue Binary Analysis Framework";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-darwin"
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = nixpkgs.lib.genAttrs supportedSystems;
      requiredPkgs =
        pkgs: with pkgs; [
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
    {
      packages = forEachSystem (
        system:
        let
          pkgs = import nixpkgs { system = system; };
        in
        {
          default = pkgs.mkDerivation {
            pname = "fugue";
            version = "0.3.0";
            src = self;
            buildInputs = requiredPkgs pkgs;
          };
        }
      );
      devShells = forEachSystem (
        system:
        let
          pkgs = import nixpkgs { system = system; };
        in
        {
          default = pkgs.mkShell {
            buildInputs = requiredPkgs pkgs;
            shellHook = ''
              export RUST_BACKTRACE=1
            '';
          };
        }
      );
    };
}
