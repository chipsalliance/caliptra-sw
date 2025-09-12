{ config, pkgs, user, fpga-boss-script, ... }:
{
  systemd.user.services.zcu-0 = {
    enable = true;
    description = "ZCU-0 Service";
    after = [ "network.target" ];
    wantedBy = [ "default.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.3"''
        ''USB_SDMUX="00048.00643"''
        ''IDENTIFIER="caliptra-bo-01"''
        ''FPGA_TARGET=""caliptra-fpga,caliptra-fpga-nightly""''
        ''IMAGE="/home/${user}/ci-images/zcu104.img"''
        ''PATH=${pkgs.usbsdmux}/bin''
      ];
    };
  };
  environment.systemPackages = with pkgs; [
      ((pkgs.writeShellScriptBin "zcu-0-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.3"
        export USB_SDMUX="00048.00643"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $USB_SDMUX "$@"
     ''))
  ];
}
