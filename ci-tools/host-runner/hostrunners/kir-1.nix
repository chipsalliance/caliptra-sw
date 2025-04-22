{ config, pkgs, user, ... }:
let
  vck-4 = pkgs.writeShellScriptBin "vck-4.sh" ''
    #!${pkgs.bash}/bin/bash
    export ZCU_FTDI="1-1.2"
    export ZCU_SDWIRE="1-1.1"
    export IDENTIFIER="4"

    caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $HOME/vck.img -- cred-tool --stage prod --fpga-target vck190 --fpga-identifier $IDENTIFIER --location kir --key-path /etc/secrets/caliptra-gce-ci-github-private-key-pem/prod
  '';
in
{
  systemd.services.vck-4 = {
    description = "VCK-4 Service";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "${user}";
      ExecStart = "${vck-4}/bin/vck-4.sh";
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
