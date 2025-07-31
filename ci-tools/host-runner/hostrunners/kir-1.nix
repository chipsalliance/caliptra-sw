{ config, pkgs, user, fpga-boss-script, ... }:
{
  systemd.user.services.vck-4 = {
    enable = true;
    description = "VCK-4 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${fpga-boss-script}/bin/fpga.sh";
      Restart = "on-failure";
      RestartSec = "15s";
      Environment = [
        ''ZCU_FTDI="1-1.2"''
        ''ZCU_SDWIRE="1-1.1"''
        ''IDENTIFIER="caliptra-kir-vck190-4"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/vck190.img"''
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
        ''ZCU_FTDI="1-1.3.4"''
        ''ZCU_SDWIRE="1-1.3.3"''
        ''IDENTIFIER="caliptra-kir-vck190-1"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/vck190.img"''
      ];
    };
  };
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
        ''ZCU_FTDI="1-1.3.2"''
        ''ZCU_SDWIRE="1-1.3.1"''
        ''IDENTIFIER="caliptra-kir-vck190-0"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/vck190.img"''
      ];
    };
  };
  environment.systemPackages = with pkgs; [
      ((pkgs.writeShellScriptBin "vck-4-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.2"
        export ZCU_SDWIRE="1-1.1"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
     ''))
      ((pkgs.writeShellScriptBin "vck-0-debug" ''
        #!${pkgs.bash}/bin/bash
        export ZCU_FTDI="1-1.3.2"
        export ZCU_SDWIRE="1-1.3.1"

        caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE "$@"
     ''))
  ];
}
