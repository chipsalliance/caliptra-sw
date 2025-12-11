{
  pkgs,
  rtool,
  fpga-boss,
  user,
  ...
}:
let
  scripts = import ./scripts.nix {
    inherit
      pkgs
      rtool
      fpga-boss
      user
      ;
  };
  mkFpgaJob =
    name: target: image:
    { ftdi, sdwire }:
    {
      systemd.user.services."${name}" = {
        enable = true;
        description = "${name} Service";
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${scripts.fpga-boss-script}/bin/fpga.sh";
          Restart = "on-failure";
          RestartSec = "15s";
          Environment = [
            ''ZCU_FTDI="${ftdi}"''
            ''ZCU_SDWIRE="${sdwire}"''
            ''IDENTIFIER="${name}"''
            ''FPGA_TARGET=""${target}""''
            ''IMAGE="${image}"''
          ];
        };
      };
      environment.systemPackages = with pkgs; [
        (
          (pkgs.writeShellScriptBin "${name}-debug" ''
            #!${pkgs.bash}/bin/bash
            export ZCU_FTDI="${ftdi}"
            export ZCU_SDWIRE="${sdwire}"

            caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
          '')
        )
      ];
    };
in
{
  mkZcuJob =
    name:
    { ftdi, sdwire }:
    (mkFpgaJob name "caliptra-fpga,caliptra-fpga-nightly" "/home/${user}/ci-images/zcu104.img" {
      ftdi = ftdi;
      sdwire = sdwire;
    });
  mkVckSubsystemJob =
    name:
    { ftdi, sdwire }:
    (mkFpgaJob name "vck190-subsystem" "/home/${user}/ci-images/caliptra-fpga-image-subsystem.img" {
      ftdi = ftdi;
      sdwire = sdwire;
    });
  mkVckCoreJob =
    name:
    { ftdi, sdwire }:
    (mkFpgaJob name "vck190" "/home/${user}/ci-images/caliptra-fpga-image-core.img" {
      ftdi = ftdi;
      sdwire = sdwire;
    });
}
