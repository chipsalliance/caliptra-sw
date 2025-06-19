
{
  description = "Caliptra Raspberry PI Host Runner Image";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs, ... }@inputs:
    let
      pkgs = nixpkgs.legacyPackages.aarch64-linux;
      rtool = pkgs.callPackage tools/rtool.nix {};
      fpga-boss = pkgs.callPackage tools/fpga-boss.nix {};
      fpga-boss-script = pkgs.writeShellScriptBin "fpga.sh" ''
        #!${pkgs.bash}/bin/bash
        export GCP_ZONE="us-central1"
        export GITHUB_ORG="chipsalliance"
        export GCP_PROJECT="caliptra-github-ci"

        RAND_POSTFIX=$(${pkgs.python3}/bin/python3 -c 'import random; print("".join(random.choice("0123456789ABCDEF") for i in range(16)))')
        ${fpga-boss}/bin/caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $IMAGE -- ${rtool}/bin/rtool jitconfig "$FPGA_TARGET" 379559 40993215 "$IDENTIFIER-$RAND_POSTFIX"
      '';
    in
    {
      nixosConfigurations."caliptra-hostrunner0" = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = {
          identifier = "0";
          user = "hostrunner";
          fpga-boss-script = fpga-boss-script;
        };
        modules = [
          ./configuration.nix
          ./hostrunners/kir-0.nix
        ];
      };
      nixosConfigurations."caliptra-hostrunner1" = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = {
          identifier = "1";
          user = "hostrunner";
          fpga-boss-script = fpga-boss-script;
        };
        modules = [
          ./configuration.nix
          ./hostrunners/kir-1.nix
        ];
      };
      nixosConfigurations."caliptra-hostrunner2" = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = {
          identifier = "2";
          user = "hostrunner";
          fpga-boss-script = fpga-boss-script;
        };
        modules = [
          ./configuration.nix
          ./hostrunners/kir-2.nix
        ];
      };
  };
}
