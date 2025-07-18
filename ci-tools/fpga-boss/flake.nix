{
  description = "A tool to manage Caliptra FPGA runners";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        caliptra-fpga-boss = with pkgs; rustPlatform.buildRustPackage {
          pname = "caliptra-fpga-boss";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [
            pkg-config
          ];
          buildInputs = [
            libftdi1
            libusb1
          ];
        };

      in
      {
        packages.default = caliptra-fpga-boss;

        apps.default = flake-utils.lib.mkApp {
          drv = caliptra-fpga-boss;
        };
      });
}

