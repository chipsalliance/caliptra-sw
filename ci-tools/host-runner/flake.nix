{
  description = "Caliptra Raspberry PI Host Runner Image";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs, ... }@inputs: rec {
    nixosConfigurations."caliptra-hostrunner0" = nixpkgs.lib.nixosSystem {
      system = "aarch64-linux";
      specialArgs = {
        identifier = "0";
        user = "hostrunner";
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
      };
      modules = [
        ./configuration.nix
        ./hostrunners/kir-1.nix
      ];
    };
  };
}
