{
  description = "NixOS SD Card Images for Caliptra FPGAs (AMD/Xilinx VCK-190 & ZCU104)";

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

      mkFpgaSystem =
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
              fpga = {
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
        vck190-core-ci = mkFpgaSystem {
          variant = "core";
          isDev = false;
        };
        vck190-core-dev = mkFpgaSystem {
          variant = "core";
          isDev = true;
        };
        vck190-subsystem-ci = mkFpgaSystem {
          variant = "subsystem";
          isDev = false;
        };
        vck190-subsystem-dev = mkFpgaSystem {
          variant = "subsystem";
          isDev = true;
        };
        zcu104-ci = mkFpgaSystem {
          variant = "zcu104";
          isDev = false;
        };
        zcu104-dev = mkFpgaSystem {
          variant = "zcu104";
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
            (mkFpgaSystem (args // { buildSystem = system; })).config.system.build.sdImage;

          bootFirmware = import ./nix/boot-firmware.nix {
            inherit buildPkgs targetPkgs;
            inherit (buildPkgs) lib;
          };

          kernelBundle = import ./nix/kernel.nix {
            pkgs = targetPkgs;
            inherit (targetPkgs) lib;
          };

          zcu104Boot = import ./nix/zcu104-boot.nix {
            inherit buildPkgs;
            inherit (buildPkgs) lib;
          };
        in
        {
          default = mkImage {
            variant = "subsystem";
            isDev = false;
          };

          # Caliptra 2.x (AMD/Xilinx Versal VCK-190)
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

          # Caliptra 1.x (AMD/Xilinx ZynqMP ZCU104)
          zcu104-ci = mkImage {
            variant = "zcu104";
            isDev = false;
          };
          zcu104-dev = mkImage {
            variant = "zcu104";
            isDev = true;
          };

          # Standalone Versal & ZCU104 boot firmware, kernel, and UIO module derivations
          bootgen = bootFirmware.bootgen;
          system-dtb = bootFirmware.systemDtb;
          arm-trusted-firmware = bootFirmware.armTrustedFirmware;
          u-boot-xlnx = bootFirmware.uBootXlnx;
          boot-bin-core = bootFirmware.bootBinCore;
          boot-bin-subsystem = bootFirmware.bootBinSubsystem;
          linux-xlnx = kernelBundle.linuxXlnx;
          boot-scr = kernelBundle.bootScr;
          zcu104-system-boot = zcu104Boot.systemBootTarball;
          zcu104-kernel-modules = zcu104Boot.kernelModules;
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
