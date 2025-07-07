{ config, pkgs, user, fpga-boss-script, ... }:
{
  systemd.services.vck-5 = {
    description = "VCK-5 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.1.3"''
        ''ZCU_SDWIRE="1-1.1.2"''
        ''IDENTIFIER="caliptra-kir-vck190-5"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/vck190.img"''
      ];
    };
  };
  systemd.services.vck-3 = {
    description = "VCK-3 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.1.1"''
        ''ZCU_SDWIRE="1-1.1.4"''
        ''IDENTIFIER="caliptra-kir-vck190-3"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/vck190.img"''
      ];
    };
  };
  systemd.services.vck-2 = {
    description = "VCK-2 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.4"''
        ''ZCU_SDWIRE="1-1.3"''
        ''IDENTIFIER="caliptra-kir-vck190-2"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/vck190.img"''
      ];
    };
  };
  environment.systemPackages = with pkgs; [
      ((pkgs.writeShellScriptBin "vck-2-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.4"
        export ZCU_SDWIRE="1-1.3"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
     ''))
      ((pkgs.writeShellScriptBin "vck-3-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.1.1"
        export ZCU_SDWIRE="1-1.1.4"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
     ''))
  ];
}
