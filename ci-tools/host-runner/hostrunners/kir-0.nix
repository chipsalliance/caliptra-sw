{ config, pkgs, user, ... }:
let
  zcu-0 = pkgs.writeShellScriptBin "zcu-0.sh" ''
    #!${pkgs.bash}/bin/bash
    export ZCU_FTDI="1-1.1.3"
    export ZCU_SDWIRE="1-1.1.4"
    export IDENTIFIER="0"

    caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $HOME/zcu104.img -- cred-tool --stage prod --fpga-target zcu104 --fpga-identifier $IDENTIFIER --location kir --key-path /etc/secrets/caliptra-gce-ci-github-private-key-pem/prod
  '';
  zcu-1 = pkgs.writeShellScriptBin "zcu-1.sh" ''
    #!${pkgs.bash}/bin/bash
    export ZCU_FTDI="1-1.1.2"
    export ZCU_SDWIRE="1-1.1.1"
    export IDENTIFIER="1"

    caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $HOME/zcu104.img -- cred-tool --stage prod --fpga-target zcu104-nightly --fpga-identifier $IDENTIFIER --location kir --key-path /etc/secrets/caliptra-gce-ci-github-private-key-pem/prod
  '';
  zcu-2 = pkgs.writeShellScriptBin "zcu-2.sh" ''
    #!${pkgs.bash}/bin/bash
    export ZCU_FTDI="1-1.2.2"
    export ZCU_SDWIRE="1-1.2.1"
    export IDENTIFIER="2"

    caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $HOME/zcu104.img -- cred-tool --stage prod --fpga-target zcu104-nightly --fpga-identifier $IDENTIFIER --location kir --key-path /etc/secrets/caliptra-gce-ci-github-private-key-pem/prod
  '';
in
{
  systemd.services.zcu-0 = {
    description = "ZCU-0 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${zcu-0}/bin/zcu-0.sh";
      Restart = "on-failure";
      RestartSec = "15s";
    };

    path = with pkgs; [
      bash
      ((pkgs.callPackage ../tools/cred-tool.nix {}))
      ((pkgs.callPackage ../tools/fpga-boss.nix {}))
    ];
  };
  systemd.services.zcu-1 = {
    description = "ZCU-1 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${zcu-1}/bin/zcu-1.sh";
      Restart = "on-failure";
      RestartSec = "15s";
    };

    path = with pkgs; [
      bash
      ((pkgs.callPackage ../tools/cred-tool.nix {}))
      ((pkgs.callPackage ../tools/fpga-boss.nix {}))
    ];
  };
  systemd.services.zcu-2 = {
    description = "ZCU-2 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${zcu-2}/bin/zcu-2.sh";
      Restart = "on-failure";
      RestartSec = "15s";
    };

    path = with pkgs; [
      bash
      ((pkgs.callPackage ../tools/cred-tool.nix {}))
      ((pkgs.callPackage ../tools/fpga-boss.nix {}))
    ];
  };
}
