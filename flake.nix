{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust-platform = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["llvm-tools-preview"];
        };

        mkScript = name: text: (pkgs.writeShellScriptBin name text);

        shellScripts = [
          (mkScript "ctest" "cargo nextest run --workspace \"$@\"")
        ];
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs;
            [
              cargo-audit
              cargo-edit
              cargo-llvm-cov
              cargo-nextest

              python315

              botan3
              openssl
            ]
            ++ [rust-platform]
            ++ shellScripts;

          RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
          BOTAN_INCLUDE_DIR = "${pkgs.botan3.dev}/include/botan-3";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        };
      }
    );
}
