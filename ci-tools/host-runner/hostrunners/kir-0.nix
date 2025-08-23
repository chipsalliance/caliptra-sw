{ config, pkgs, user, fpga-boss-script, ... }:
{
  systemd.user.services.zcu-0 = {
    enable = true;
    description = "ZCU-0 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.1.3"''
        ''ZCU_SDWIRE="1-1.1.4"''
        ''IDENTIFIER="caliptra-kir-0"''
        ''FPGA_TARGET=""caliptra-fpga,caliptra-fpga-nightly""''
        ''IMAGE="/home/${user}/ci-images/zcu104.img"''
      ];
    };
  };
  systemd.user.services.zcu-1 = {
    enable = true;
    description = "ZCU-1 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.1.2"''
        ''ZCU_SDWIRE="1-1.1.1"''
        ''IDENTIFIER="caliptra-kir-1"''
        ''FPGA_TARGET="caliptra-fpga,caliptra-fpga-nightly"''
        ''IMAGE="/home/${user}/ci-images/zcu104.img"''
      ];
    };
  };
  systemd.user.services.zcu-2 = {
    enable = true;
    description = "ZCU-2 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.2.2"''
        ''ZCU_SDWIRE="1-1.2.1"''
        ''IDENTIFIER="caliptra-kir-2"''
        ''FPGA_TARGET="caliptra-fpga,caliptra-fpga-nightly"''
        ''IMAGE="/home/${user}/ci-images/zcu104.img"''
      ];
    };
  };
  environment.systemPackages = with pkgs; [
      ((pkgs.writeShellScriptBin "zcu-0-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.1.3"
        export ZCU_SDWIRE="1-1.1.4"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
     ''))
  ];
}
