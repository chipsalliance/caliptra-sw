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
    description = "VCK-0 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.2.1.1"''
        ''ZCU_SDWIRE="1-1.2.4"''
        ''IDENTIFIER="caliptra-svl-vck190-0"''
        ''FPGA_TARGET="vck190-subsystem"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-subsystem.img"''
      ];
    };
  };
  systemd.user.services.vck-1 = {
    enable = true;
    description = "VCK-1 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.2.2"''
        ''ZCU_SDWIRE="1-1.2.3"''
        ''IDENTIFIER="caliptra-svl-vck190-1"''
        ''FPGA_TARGET="vck190-subsystem"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-subsystem.img"''
      ];
    };
  };
  # VCK-2 is not part of the CI pool and used for development at this time.
  environment.systemPackages = with pkgs; [
    (
      (pkgs.writeShellScriptBin "vck-0-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.2.1.1"
        export ZCU_SDWIRE="1-1.2.4"
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
    (
      (pkgs.writeShellScriptBin "vck-2-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.2.1.2"
        export ZCU_SDWIRE="1-1.2.1.3"
        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
      '')
    )
  ];
}
