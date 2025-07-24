# Nix configuration for a caliptra fpga runner host

{ pkgs, identifier, user, lib, rtool, ... }:
let 
    update-fpga-script = pkgs.writeShellScriptBin "update-fpga-image" ''
      export GCP_ZONE="us-central1"
      export GITHUB_ORG="chipsalliance"
      export GCP_PROJECT="caliptra-github-ci"

      set -eux
      cd /home/${user}
      ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml caliptra-fpga-image main > caliptra-fpga-image.zip
      ${pkgs.unzip}/bin/unzip caliptra-fpga-image.zip
      mv image.img zcu104.img
      rm caliptra-fpga-image.zip
    '';
in
{
  imports = [
    ./hardware-configuration.nix
  ];

  # Keep SD card from running out of room
  nix.gc.automatic = true;
  nix.gc.persistent = true;
  nix.gc.dates = "weekly";

  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;

  time.timeZone = "America/Los_Angeles";
  i18n.defaultLocale = "en_US.UTF-8";

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  # We want to be able to update this system from a remote host.
  # The remote host will ssh in as `user` to mutate the system.
  nix.settings.trusted-users = [ "${user}" ];

  networking.networkmanager.enable = true;
  networking.hostName = "caliptra-hostrunner${identifier}";

  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;

  security.sudo.wheelNeedsPassword = true;

  users.mutableUsers = false;
  users.users."${user}" = {
    isNormalUser = true;
    hashedPassword = lib.strings.trim (builtins.readFile ./secrets/${user}-pass);
    extraGroups = [ "wheel" "networkmanager" ];
    # Add your SSH public key here to gain SSH access to the host runner.
    # Remove keys you do not trust
    openssh.authorizedKeys.keys = [
        # clundin Mac
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDKTJ6unwymfvdFSTNAXo+wjaX1l2SFPgeSgK/xzC7ex3oGR2ihCg/8luQt1e6FKnbqV83O2v0AT/aRw9p9sEjY7HGNDz+0nQ6lezi4XAuqJMOMshzVlqv4hZJLb8Ab2PMma0se15h1LhnfSUpttv7cDgdLXHqh2kizMQ39l62Lu4j2ITJKFhqW1v7Ez74uo2o++We6EHU2PRZhyKV9tKbYXojOyow+abUXKMfXy01iCSunaQq6KRB6Jl5TskMVmGSz0rUnjyxLCCPEA2h7D0lgQviLuJQtIl/jFYu8QFNqaVwHDHiEUpNfcfQGx6S7hpSs7CdPD29YQSka9TovICyD3dCKGn+tpfRQDmZSTR8Qnqv4mNtxKPcitpMFNVL9V6Echqy83rlo5CgO1tEsL/6g0WEm6nrFBMs/szUfv1qs4/4wL0PsNit1ArxfqYXVaDzGisvA+Y4yRl2IsMPaI7TzB6uDSR0j31jZXSGR8vqPG9rF+aGobF21OfWGHI8Ddc= clundin@clundin-macbookpro.roam.internal"
        # clundin Workstation
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDohnyJgm7nztWkxtKaqds13IHJMYpoV2VozRs5wIbct2R98lmyATIR+pOypPv/uv++KnDTUV68/Pt+SFZS6VcOBj/SfDqniqi5/Zmj5qL0dRfLfr4RE1ET7gMPMpvbynUEaXiaochSInikdToDwUeUfhNfs1JGGIbOsoNNhBYAKuNTBo7DXpOUuq8t6oBMqvYWWtCN+kAagkf3tyi94Br52GS++9i7q3RZnvHtw79FW5Sc4xZtuiBqs7aKsK/pplKC7V6emcf0zM1F49knZR+UmLvHhRXzbyxJPyDHgZFGcu7SeDCikAn/2mKxIr8gHjyVSZ5JwOuHekQrVRgwT+CVYBc6AsvCe5aRsrUDJC7TZHsWUVKkaXXDyASYy87wTy+IE3BCZVZmjjZ9OufX7jqXT/lenJbaOn9240e5pSydOzT97tVIuL8rRL+6m00cBsxLJcsFjmrGreX3M2T37IifICpFUDaZJYkVcrKvUWXIdgqHECpQgo7YmLlTcC/hP/0= clundin@clundin6.kir.corp.google.com "
        # zhalvorsen
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBLCee6PZ63j9MXxo2LIB6K7I5WmIKJAWdww922p9klsKVhLkMpNPXkLtYaf44GDLSmNO1j2stkXw174agt722rAa6fNInSCY8HPpAlyAJ7xELEGDOb5FfQVJU5ruGYJ7LQ== zhalvorsen@zhalvorsen.c.googlers.com"
      ];
  };

  environment.systemPackages = with pkgs; [
    neovim
    curl
    git
    tmux
    libftdi1
    fzf
    ripgrep
    fd
    jq
    unzip
    update-fpga-script
    ((pkgs.callPackage ./tools/fpga-boss.nix {}))
    rtool
  ];

  programs.zsh.enable = true;
  services.udev.extraRules = ''
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6011", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="04e8", ATTRS{idProduct}=="6001", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="2640", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="4050", OWNER="${user}", GROUP="users"
    '';

  # Host runner secrets
  environment.etc = {
    # Github Key for fpga boss
     github-key = {
      text = builtins.readFile ./secrets/google/prod;
      mode = "0400";
      user = "${user}";
      target = "secrets/caliptra-gce-ci-github-private-key-pem/latest";
    };
  };

  # Keep logs for 2 weeks, we generally only need to look at them when things break.
  services.journald.extraConfig = "MaxRetentionSec=2weeks";

  systemd.timers."update-fpga-image" = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "Wed *-*-* 05:00:00";
      Persistent = true;
    };
  };

  systemd.services."update-fpga-image" = {
    serviceConfig = {
      Type = "oneshot";
      User = "${user}";
      ExecStart = "${update-fpga-script}/bin/update-fpga-image";
    };
  };
}
