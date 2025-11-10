{
  config,
  pkgs,
  user,
  fpga-boss-script,
  ...
}:
{
  systemd.user.services.vck-0 = {
    enable = true;
    description = "VCK-SVL-0 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.2.1.2"''
        ''ZCU_SDWIRE="1-1.2.1.1"''
        ''IDENTIFIER="caliptra-svl-vck190-0"''
        ''FPGA_TARGET="vck190-subsystem-2.0"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-subsystem-2.0.img"''
      ];
    };
  };
  environment.systemPackages = with pkgs; [
    (
      (pkgs.writeShellScriptBin "vck-0-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.2.1.2"
        export ZCU_SDWIRE="1-1.2.1.1"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
      '')
    )
    (
      (pkgs.writeShellScriptBin "vck-1-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.2.2"
        export ZCU_SDWIRE="1-1.2.3"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
      '')
    )
  ];
}
