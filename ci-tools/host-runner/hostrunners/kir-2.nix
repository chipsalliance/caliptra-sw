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
    (fpga_service.mkVckSubsystemJob "caliptra-kir-vck-2" {
      ftdi = "1-1.4";
      sdwire = "1-1.3";
    })
    # Note don't start this one, zhalvorsen dev FPGA
    (fpga_service.mkVckSubsystemJob "caliptra-kir-vck-3" {
      ftdi = "1-1.2.3";
      sdwire = "1-1.2.4";
    })
    (fpga_service.mkVckSubsystemJob "caliptra-kir-vck-5" {
      ftdi = "1-1.2.1.1";
      sdwire = "1-1.2.1.2";
    })
    # Note don't start this one, clundin dev FPGA
    (fpga_service.mkVckCoreJob "caliptra-kir-vck-6" {
      ftdi = "1-1.2.1.4";
      sdwire = "1-1.2.1.3";
    })
  ];
}
