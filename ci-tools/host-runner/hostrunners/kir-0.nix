{ config, pkgs, user, fpga-boss-script, ... }:
{
  systemd.services.zcu-0 = {
    description = "ZCU-0 Service";
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
        ''ZCU_SDWIRE="1-1.1.4"''
        ''IDENTIFIER="caliptra-kir-0"''
        ''FPGA_TARGET="caliptra-fpga"''
        ''IMAGE="/home/${user}/zcu104.img"''
      ];
    };
  };
  systemd.services.zcu-1 = {
    description = "ZCU-1 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.1.2"''
        ''ZCU_SDWIRE="1-1.1.1"''
        ''IDENTIFIER="caliptra-kir-1"''
        ''FPGA_TARGET="caliptra-fpga,caliptra-fpga-nightly"''
        ''IMAGE="/home/${user}/zcu104.img"''
      ];
    };
  };
  systemd.services.zcu-2 = {
    description = "ZCU-2 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.2.2"''
        ''ZCU_SDWIRE="1-1.2.1"''
        ''IDENTIFIER="caliptra-kir-2"''
        ''FPGA_TARGET="caliptra-fpga,caliptra-fpga-nightly"''
        ''IMAGE="/home/${user}/zcu104.img"''
      ];
    };
  };
}
