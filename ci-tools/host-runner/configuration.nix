# Nix configuration for a caliptra fpga runner host

{
  pkgs,
  identifier,
  user,
  lib,
  rtool,
  fpga-boss,
  ssh_keys,
  ...
}:
let
  download-image-script = pkgs.writeShellScriptBin "download-fpga-image" ''
    export GCP_ZONE="us-central1"
    export GITHUB_ORG="chipsalliance"
    export GCP_PROJECT="caliptra-github-ci"
    ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image.yml "$@"
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
    DATE_SUFFIX=$(date +%Y%m%d)
    (mv zcu104.img zcu104.img.old."$DATE_SUFFIX" || true)
    mv image.img zcu104.img
    rm caliptra-fpga-image.zip

    for VARIANT in "caliptra-fpga-image-core" "caliptra-fpga-image-subsystem-2.0" "caliptra-fpga-image-subsystem-2.1"; do
        ${rtool}/bin/rtool download_artifact 379559 40993215 fpga-image-2.x.yml $VARIANT main > $VARIANT.zip
        ${pkgs.unzip}/bin/unzip $VARIANT.zip
        (mv $VARIANT.img $VARIANT.img.old."$DATE_SUFFIX" || true)
        mv image.img $VARIANT.img
        rm $VARIANT.zip
     done
  '';
  cleanup-old-images-script = pkgs.writeShellScriptBin "cleanup-old-images" ''
    set -eux
    cd /home/${user}/ci-images
    ${pkgs.fd}/bin/fd --glob "*.img*.old" --change-older-than "4 weeks" -X rm
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
    extraGroups = [
      "wheel"
      "networkmanager"
    ];

    # The fpga ci runner services are defined as systemd user services.
    # These services are first started when the user is logged in.
    # To start them on boot, enable lingering (loginctl enable-linger).
    linger = true;

    # Add your SSH public key here to gain SSH access to the host runner.
    # Remove keys you do not trust
    openssh.authorizedKeys.keys = ssh_keys;
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
    rtool
    fpga-boss
    picocom
    usbsdmux
    update-fpga-script
    download-image-script
    cleanup-old-images-script
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

  systemd.timers."cleanup-old-images" = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "Sat *-*-* 05:00:00";
      Persistent = true;
    };
  };

  systemd.services."cleanup-old-images" = {
    serviceConfig = {
      Type = "oneshot";
      User = "${user}";
      ExecStart = "${cleanup-old-images-script}/bin/cleanup-old-images";
    };
  };
}
