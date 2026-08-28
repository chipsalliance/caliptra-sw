{
  description = "Development environment for caliptra-sw";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    mjolnir = {
      url = "github:chipsalliance/mjolnir/d53222604da502e82a41944c4b3229ce7ca69ad6";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, mjolnir, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustup
            pkg-config
            openssl
            gcc
            taplo
            cargo-nextest
          ];
          shellHook = ''
            # Ensure the toolchains are installed
            rustup toolchain install $(grep channel rust-toolchain.toml | cut -d'"' -f2)
            rustup target add riscv32imc-unknown-none-elf
          '';
        };
      in
      {
        devShells.default = devShell;

        packages = mjolnir.lib.discoverProjectJobs {
          inherit pkgs devShell;
          mjolnirApp = mjolnir.packages.${system}.mjolnir-app;
          projectDir = ./tools/mjolnir;
          deployPackages = {
            inherit (mjolnir.packages.${system}) deploy-gcs-runs;
          };
        };
      }
    );
}
