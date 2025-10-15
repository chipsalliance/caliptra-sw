{ config, pkgs, user, fpga-boss-script, ... }:
{
  systemd.user.services.vck-7 = {
    enable = true;
    description = "VCK-7 Service";
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
        ''IDENTIFIER="caliptra-kir-vck190-7"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-core.img"''
      ];
    };
  };
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
        ''ZCU_FTDI="1-1.3.3"''
        ''ZCU_SDWIRE="1-1.3.4"''
        ''IDENTIFIER="caliptra-kir-vck190-4"''
        ''FPGA_TARGET="vck190-mcu,vck190-subsystem-2.0"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-subsystem-2.0.img"''
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
        ''ZCU_FTDI="1-1.3.1.1"''
        ''ZCU_SDWIRE="1-1.3.1.2"''
        ''IDENTIFIER="caliptra-kir-vck190-1"''
        ''FPGA_TARGET="vck190-subsystem-2.1"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-subsystem-2.1.img"''
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
        ''ZCU_FTDI="1-1.3.1.3"''
        ''ZCU_SDWIRE="1-1.3.1.4"''
        ''IDENTIFIER="caliptra-kir-vck190-0"''
        ''FPGA_TARGET="vck190"''
        ''IMAGE="/home/${user}/ci-images/caliptra-fpga-image-core.img"''
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
