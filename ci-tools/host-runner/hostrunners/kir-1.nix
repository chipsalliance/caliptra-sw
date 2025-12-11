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
    (fpga_service.mkVckCoreJob "caliptra-kir-vck-0" {
      ftdi = "1-1.3.1.3";
      sdwire = "1-1.3.1.4";
    })
    (fpga_service.mkVckCoreJob "caliptra-kir-vck-1" {
      ftdi = "1-1.3.1.1";
      sdwire = "1-1.3.1.2";
    })
    (fpga_service.mkVckCoreJob "caliptra-kir-vck-4" {
      ftdi = "1-1.3.3";
      sdwire = "1-1.3.4";
    })
    (fpga_service.mkVckSubsystemJob "caliptra-kir-vck-7" {
      ftdi = "1-1.2";
      sdwire = "1-1.1";
    })
  ];
}
