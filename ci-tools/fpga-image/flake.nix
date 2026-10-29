{
  description = "NixOS SD Card Image for Caliptra AMD/Xilinx Versal VCK-190 FPGA";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      mkVck190System =
        {
          variant,
          isDev,
          xsa ? null,
          buildSystem ? "x86_64-linux",
        }:
        let
          buildPkgs = nixpkgs.legacyPackages.${buildSystem};
          targetPkgs =
            if buildSystem == "aarch64-linux" then
              nixpkgs.legacyPackages.aarch64-linux
            else
              buildPkgs.pkgsCross.aarch64-multiplatform;
        in
        nixpkgs.lib.nixosSystem {
          system = "aarch64-linux";
          specialArgs = {
            inherit buildPkgs targetPkgs;
          };
          modules = [
            ./nix/configuration.nix
            {
              vck190 = {
                inherit
                  variant
                  isDev
                  xsa
                  ;
              };
            }
          ];
        };
    in
    {
      nixosConfigurations = {
        vck190-core-ci = mkVck190System {
          variant = "core";
          isDev = false;
        };
        vck190-core-dev = mkVck190System {
          variant = "core";
          isDev = true;
        };
        vck190-subsystem-ci = mkVck190System {
          variant = "subsystem";
          isDev = false;
        };
        vck190-subsystem-dev = mkVck190System {
          variant = "subsystem";
          isDev = true;
        };
      };

      packages = forAllSystems (
        system:
        let
          buildPkgs = nixpkgs.legacyPackages.${system};
          targetPkgs =
            if system == "aarch64-linux" then
              nixpkgs.legacyPackages.aarch64-linux
            else
              buildPkgs.pkgsCross.aarch64-multiplatform;

          mkImage =
            args:
            (mkVck190System (args // { buildSystem = system; })).config.system.build.sdImage;

          bootFirmware = import ./nix/boot-firmware.nix {
            inherit buildPkgs targetPkgs;
            inherit (buildPkgs) lib;
          };

          kernelBundle = import ./nix/kernel.nix {
            pkgs = targetPkgs;
            inherit (targetPkgs) lib;
          };
        in
        {
          default = mkImage {
            variant = "subsystem";
            isDev = false;
          };

          vck190-core-ci = mkImage {
            variant = "core";
            isDev = false;
          };
          vck190-core-dev = mkImage {
            variant = "core";
            isDev = true;
          };
          vck190-subsystem-ci = mkImage {
            variant = "subsystem";
            isDev = false;
          };
          vck190-subsystem-dev = mkImage {
            variant = "subsystem";
            isDev = true;
          };

          # Standalone Versal boot firmware, kernel, and UIO module derivations
          bootgen = bootFirmware.bootgen;
          system-dtb = bootFirmware.systemDtb;
          arm-trusted-firmware = bootFirmware.armTrustedFirmware;
          u-boot-xlnx = bootFirmware.uBootXlnx;
          boot-bin-core = bootFirmware.bootBinCore;
          boot-bin-subsystem = bootFirmware.bootBinSubsystem;
          linux-xlnx = kernelBundle.linuxXlnx;
          boot-scr = kernelBundle.bootScr;
          io-module-core = targetPkgs.callPackage ./nix/io-module.nix {
            kernel = kernelBundle.linuxXlnx;
            variant = "core";
          };
          io-module-subsystem = targetPkgs.callPackage ./nix/io-module.nix {
            kernel = kernelBundle.linuxXlnx;
            variant = "subsystem";
          };
        }
      );
    };
}
