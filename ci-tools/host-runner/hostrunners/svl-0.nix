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
    (fpga_service.mkVckSubsystemJob "caliptra-svl-vck-0" {
      ftdi = "1-1.2.1.1";
      sdwire = "1-1.2.4";
    })
    (fpga_service.mkVckSubsystemJob "caliptra-svl-vck-1" {
      ftdi = "1-1.2.2";
      sdwire = "1-1.2.3";
    })
    # Note don't start this one. It's a dev board
    (fpga_service.mkVckSubsystemJob "caliptra-svl-vck-2" {
      ftdi = "1-1.2.1.2";
      sdwire = "1-1.2.1.3";
    })
  ];
}
