{
  config,
  lib,
  pkgs,
  user,
  rtool,
  fpga-boss,
  ...
}:
let
  fpga_service = import ../fpga-service.nix {
    inherit
      pkgs
      rtool
      fpga-boss
      user
      ;
  };
in
{
  config = lib.mkMerge [
    (fpga_service.mkZcuJob "caliptra-kir-zcu-0" {
      ftdi = "1-1.1.3";
      sdwire = "1-1.1.4";
    })
    (fpga_service.mkZcuJob "caliptra-kir-zcu-1" {
      ftdi = "1-1.1.2";
      sdwire = "1-1.1.1";
    })
    (fpga_service.mkZcuJob "caliptra-kir-zcu-2" {
      ftdi = "1-1.2.2";
      sdwire = "1-1.2.1";
    })
  ];
}
