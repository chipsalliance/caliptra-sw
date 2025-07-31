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
        ''USBSDMUX_ID="00048.00643"''
        ''IDENTIFIER="caliptra-bo-0"''
        ''FPGA_TARGET="caliptra-fpga"''
        ''IMAGE="/home/${user}/zcu104.img"''
      ];
    };
  };
}
