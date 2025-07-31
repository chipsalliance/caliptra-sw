# Nix configuration for a caliptra fpga runner host

{ pkgs, identifier, user, lib, rtool, ... }:
let 
    download-image-script = pkgs.writeShellScriptBin "download-fpga-image" ''
      export GCP_ZONE="us-central1"
      export GITHUB_ORG="chipsalliance"
      export GCP_PROJECT="caliptra-github-ci"
      ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml caliptra-fpga-image "$@"
    '';
    update-bitstream-petalinux = pkgs.writeShellScriptBin "update-bitstream-petalinux" ''
      set -eux
      BITSTREAM=$1
      IMAGE=$2
      LOSETUP=$(losetup --show -Pf $IMAGE)
      WORK_DIR=$(mktemp -d)

      pushd $WORK_DIR
      mkdir mnt
      mount "''${LOSETUP}p1" $PWD/mnt
      cp $BITSTREAM $PWD/mnt/BOOT.BIN
      umount  $PWD/mnt
      losetup -d $LOSETUP
      popd
    '';
    update-bitstream-ubuntu = pkgs.writeShellScriptBin "update-bitstream-ubuntu" ''
      set -eux
      BITSTREAM=$1
      IMAGE=$2
      LOSETUP=$(losetup --show -Pf $IMAGE)
      WORK_DIR=$(mktemp -d)

      pushd $WORK_DIR
      mkdir mnt
      mount "''${LOSETUP}p1" $PWD/mnt
      cp $BITSTREAM $PWD/mnt/boot1900.bin
      umount  $PWD/mnt
      losetup -d $LOSETUP
      popd
    '';
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
        # clundin 
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLxRYcd9xKpj9UK5ptbRGKqcNw1mTzwS2dhn3gPWTcjfzeFbgb5PK17fR6BVH7PDIHggYKL+vOVaBnekoWWSIPQ= publickey"
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
    download-image-script
    update-bitstream-petalinux
    update-bitstream-ubuntu
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
