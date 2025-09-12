{
  description = "Caliptra Raspberry PI Host Runner Image";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    rtool.url = "github:chipsalliance/caliptra-sw?dir=ci-tools/github-runner";
    # TODO: FPGA boss crashes the usb stack if built from a flake currently.
    # fpga-boss.url = "github:clundin25/caliptra-sw?dir=ci-tools/fpga-boss&ref=fpga-boss-token";
  };

  outputs = { self, nixpkgs, rtool, ... }@inputs:
    let
      pkgs = nixpkgs.legacyPackages.aarch64-linux;
      rtool-bin = rtool.packages.aarch64-linux.default;
      fpga-boss-bin = pkgs.callPackage tools/fpga-boss.nix {};
      fpga-boss-script = pkgs.writeShellScriptBin "fpga.sh" ''
        #!${pkgs.bash}/bin/bash
        export GCP_ZONE="us-central1"
        export GITHUB_ORG="chipsalliance"
        export GCP_PROJECT="caliptra-github-ci"

        RAND_POSTFIX=$(${pkgs.python3}/bin/python3 -c 'import random; print("".join(random.choice("0123456789ABCDEF") for i in range(16)))')

        # check if we operate on ZCU_SDWIRE or USBSDMUX
        if [[ -z $USB_SDMUX ]] && [[ -n $ZCU_SDWIRE ]]; then
          SD_MUX="--sdwire $ZCU_SDWIRE"
        elif [[ -n $USB_SDMUX ]] && [[ -z $ZCU_SDWIRE ]]; then
          SD_MUX="--usbsdmux $USB_SDMUX"
        else
          echo "Invalid combination of ZCU_SDWIRE and USB_SDMUX"
          exit 1
        fi

        ${fpga-boss-bin}/bin/caliptra-fpga-boss --zcu104 $ZCU_FTDI $SD_MUX serve $IMAGE -- ${rtool-bin}/bin/rtool jitconfig "$FPGA_TARGET" 379559 40993215 "$IDENTIFIER-$RAND_POSTFIX"
      '';
    in
    {
      nixosConfigurations."caliptra-hostrunner0" = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = {
          identifier = "0";
          user = "hostrunner";
          fpga-boss-script = fpga-boss-script;
          rtool = rtool-bin;
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
          rtool = rtool-bin;
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
          rtool = rtool-bin;
        };
        modules = [
          ./configuration.nix
          ./hostrunners/kir-2.nix
        ];
      };
      nixosConfigurations."caliptra-hostrunner-bo0" = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = {
          identifier = "0";
          user = "hostrunner";
          fpga-boss-script = fpga-boss-script;
          rtool = rtool-bin;
        };
        modules = [
          ./configuration.nix
          ./hostrunners/bo-0.nix
        ];
      };
  };
}
