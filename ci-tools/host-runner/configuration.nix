# Nix configuration for a caliptra fpga runner host

{ pkgs, identifier, user, lib, rtool, ... }:
let 
    download-image-script = pkgs.writeShellScriptBin "download-fpga-image" ''
      export GCP_ZONE="us-central1"
      export GITHUB_ORG="chipsalliance"
      export GCP_PROJECT="caliptra-github-ci"
      ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml "$@"
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

      cd /home/${user}
      set -eux
      mkdir -p ci-images
      pushd ci-images

      ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml caliptra-fpga-image main > caliptra-fpga-image.zip
      ${pkgs.unzip}/bin/unzip caliptra-fpga-image.zip
      (mv zcu104.img zcu104.img.old || true)
      mv image.img zcu104.img
      rm caliptra-fpga-image.zip

      for VARIANT in "caliptra-fpga-image-core-2.0" "caliptra-fpga-image-core-2.1" "caliptra-fpga-image-subsystem-2.0" "caliptra-fpga-image-subsystem-2.1"; do
          ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml $VARIANT main-2.x > $VARIANT.zip
          ${pkgs.unzip}/bin/unzip $VARIANT.zip
          (mv $VARIANT.img $VARIANT.img.old || true)
          mv image.img $VARIANT.img
          rm $VARIANT.zip
       done
    '';
in
{
  imports = [
    ./hardware-configuration.nix
  ];
  system.stateVersion = "25.05";

  # Keep SD card from running out of room
  nix.gc.automatic = true;
  nix.gc.persistent = true;
  nix.gc.dates = "weekly";

  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;

  # we need the sg module loaded for usbsdmux, see
  # https://github.com/linux-automation/usbsdmux?tab=readme-ov-file#troubleshooting
  boot.kernelModules = [
    "sg"
  ];

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

    # The fpga ci runner services are defined as systemd user services.
    # These services are first started when the user is logged in.
    # To start them on boot, enable lingering (loginctl enable-linger).
    linger = true;
    
    # Add your SSH public key here to gain SSH access to the host runner.
    # Remove keys you do not trust
    openssh.authorizedKeys.keys = [
        # clundin 
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLxRYcd9xKpj9UK5ptbRGKqcNw1mTzwS2dhn3gPWTcjfzeFbgb5PK17fR6BVH7PDIHggYKL+vOVaBnekoWWSIPQ= publickey"
        # zhalvorsen
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBLCee6PZ63j9MXxo2LIB6K7I5WmIKJAWdww922p9klsKVhLkMpNPXkLtYaf44GDLSmNO1j2stkXw174agt722rAa6fNInSCY8HPpAlyAJ7xELEGDOb5FfQVJU5ruGYJ7LQ== zhalvorsen@zhalvorsen.c.googlers.com"
        # ttrippel
        "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAC3/lGx3rPr9Nns3aAS8faxKHOj/jgqLNFpjfXehz2kGhNC2EGRibXBHHP738KEG+rjA8HOsG8oHFmTFcOBJf+UqgDNmIfx7M5Db3cEgvhMcZSWck3Nb6ouIBwVchFgAupohpKmGroNuLB5QDuOE3cA8U7zN3y1L8uhUrDAxNPmS2Dvag== ttrippel@ttrippel.svl.corp.google.com"
        # jhand
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNAmcxogmvhKGQy/kd5R+uB382XiSb1p/hlqx/lJv3IcxT3JDVk2cRuVxipirplizT6g5+a5FWH6fGrOizQ/Rd0= publickey"
        # leongross
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjT61pnWcD2+LDTEQLoSJgdAJ0cTuLEFY0FC6smSJx0LD2Liep3aEM/+kKOg7Hbnl02UbT+OQspGBqlzxjZdXk="
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
    picocom
    usbsdmux
  ];

  programs.zsh.enable = true;
  services.udev.extraRules = ''
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6011", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="04e8", ATTRS{idProduct}=="6001", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="2640", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="4050", OWNER="${user}", GROUP="users"

    # usbsdmux
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="4041", OWNER="${user}", GROUP="users"
    SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="2640", OWNER="${user}", GROUP="users"
    '';
  services.udev.packages = [ pkgs.usbsdmux ];

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
