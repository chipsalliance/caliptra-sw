{
  description = "A tool for working with the Caliptra GitHub CI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rtool =
          with pkgs;
          buildGoModule {
            pname = "rtool";
            version = "0.1.0";
            src = ./.;
            proxyVendor = true;
            vendorHash = "sha256-J/WUpXDgugv3v7m/VGlHrW9J1IxuaWB6TQ7v2Us8or0=";
          };
      in
      {
        packages.default = rtool;

        apps.default = flake-utils.lib.mkApp {
          drv = rtool;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
          ];
        };
      }
    );
}
