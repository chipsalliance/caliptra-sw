# Licensed under the Apache-2.0 license
#
# Declarative NixOS configuration for the AMD/Xilinx Versal VCK-190 FPGA image.

{
  config,
  lib,
  pkgs,
  buildPkgs ? pkgs.buildPackages,
  targetPkgs ? pkgs,
  ...
}:

let
  cfg = config.vck190;
  sshKeys = import ./ssh-keys.nix;

  vck190KernelBundle = import ./kernel.nix {
    pkgs = targetPkgs;
    inherit (targetPkgs) lib;
  };

  nixIoModule = targetPkgs.callPackage ./io-module.nix {
    kernel = vck190KernelBundle.linuxXlnx;
    variant = cfg.variant;
  };

  # Deterministic, board-unique MAC address generator reading `/sys/block/mmcblk0/device/cid`
  setMacAddressScript = pkgs.writeShellApplication {
    name = "set-mac-address";
    runtimeInputs = with pkgs; [
      coreutils
      findutils
      gnugrep
      gawk
      iproute2
    ];
    text = ''
      IFACE="''${1:-end0}"

      get_hardware_seed() {
        # SD Card CID (128-bit unique hardware card identification register on the boot SD card)
        if [ -f /sys/block/mmcblk0/device/cid ]; then
          local cid
          cid=$(tr -d '\n\r\0' < /sys/block/mmcblk0/device/cid 2>/dev/null | xargs)
          if [ -n "$cid" ]; then
            echo "$cid"
            return 0
          fi
        fi

        # Fallback seed if SD card CID is unavailable (e.g. QEMU or container)
        echo "caliptra-fpga-default-seed"
      }

      SEED=$(get_hardware_seed)
      HASH=$(echo -n "$SEED" | sha256sum | awk '{print $1}')

      # Construct locally administered unicast MAC address (02:xx:xx:xx:xx:xx)
      MAC="02:''${HASH:0:2}:''${HASH:2:2}:''${HASH:4:2}:''${HASH:6:2}:''${HASH:8:2}"

      if [ "''${1:-}" = "--print" ]; then
        echo "$MAC"
        exit 0
      fi

      if ip link show "$IFACE" >/dev/null 2>&1; then
        CURRENT_MAC=$(ip link show "$IFACE" | grep -oE 'link/ether [0-9a-fA-F:]+' | awk '{print $2}')
        if [ "$CURRENT_MAC" != "$MAC" ]; then
          echo "Setting MAC address for $IFACE to $MAC (seed: $SEED)"
          ip link set dev "$IFACE" down 2>/dev/null || true
          ip link set dev "$IFACE" address "$MAC"
          ip link set dev "$IFACE" up 2>/dev/null || true
        fi
      fi
    '';
  };

  # Startup script executed on `/dev/ttyAMA0` that communicates with `fpga-boss` over UART
  startupScript = pkgs.writeShellApplication {
    name = "startup-script";
    runtimeInputs = with pkgs; [
      coreutils
      systemd
      util-linux
      su
      bashInteractive
      github-runner
    ];
    text = ''
      # Developer mode (mutable filesystem)
      if [[ -f "/etc/no_overlayfs" ]]; then
        echo "Developer mode: Skipping CI startup logic."
        systemctl start resize-rootfs.service || true
        exec login -f root
      else
        # CI mode (overlaid writable filesystem)
        echo "CI mode: Starting command loop..."

        runner_jitconfig() {
          echo "Executing GHA runner"
          su runner -c "RUNNER_ROOT=/home/runner/.github-runner /home/runner/run.sh --jitconfig \"''${cmd_array[1]}\"" || true
          echo "GHA runner complete"
        }

        # Emit sentinel telling fpga-boss (listening via UART) we are ready for input
        echo "36668aa492b1c83cdd3ade8466a0153d --- Command input"
        echo "Available commands:"
        echo "  runner-jitconfig <base64>"
        echo "  login"
        read -r -e -p "> " cmd || true

        read -r -a cmd_array <<< "$cmd"
        if [[ "$cmd" == "login" ]]; then
          login -f root
        elif [[ "''${cmd_array[0]:-}" == "runner-jitconfig" ]]; then
          runner_jitconfig
        else
          echo "Unknown command $cmd"
        fi

        # Emit sentinel telling fpga-boss we are done and can be reset
        echo "3297327285280f1ffb8b57222e0a5033 --- ACTION IS COMPLETE"

        login -f root
        shutdown -h now
      fi
    '';
  };

  # Partition 3 online resize script for `dev` images
  resizeRootfsScript = pkgs.writeShellApplication {
    name = "resize-rootfs";
    runtimeInputs = with pkgs; [
      cloud-utils
      e2fsprogs
    ];
    text = ''
      set -x
      growpart /dev/mmcblk0 3 || true
      resize2fs /dev/mmcblk0p3
    '';
  };

  # Stub `podman` binary so `cargo xtask` host checks pass when run directly on the FPGA
  podmanStub = pkgs.writeShellScriptBin "podman" ''
    echo "stub"
  '';
in
{
  imports = [
    ./sd-image-vck190.nix
  ];

  system.stateVersion = "25.11";

  # Boot & Kernel configuration:
  # The Versal boot chain (BOOT.BIN -> U-Boot -> boot.scr -> Image -> /usr/sbin/overlay-mount.sh)
  # boots directly into partition 3 without a NixOS stage-1 initrd.
  # Kernel (`linux-xlnx`) and `io_module` are registered with NixOS so `systemd-modules-load`
  # automatically loads `io_module` on boot.
  boot.loader.grub.enable = false;
  boot.initrd.enable = false;
  system.build.initialRamdisk =
    buildPkgs.runCommand "dummy-initrd" { }
      "mkdir -p $out; touch $out/${config.system.boot.loader.initrdFile}";
  boot.kernel.enable = true;
  boot.kernelPackages = pkgs.linuxPackagesFor vck190KernelBundle.linuxXlnx;
  boot.extraModulePackages = [ nixIoModule ];
  boot.kernelModules = [ "io_module" ];

  services.udev.extraRules = ''
    SUBSYSTEM=="uio", MODE="0666"
  '';

  # Root filesystem declaration matching `overlay-mount.sh`
  fileSystems."/" =
    if cfg.isDev then
      {
        device = "/dev/mmcblk0p3";
        fsType = "ext4";
      }
    else
      {
        device = "overlay";
        fsType = "overlay";
        options = [ "defaults" ];
      };

  # Kernel sysctls matching `build.sh` lines 46-49
  boot.kernel.sysctl = {
    "kernel.softlockup_panic" = 1;
    "kernel.softlockup_all_cpu_backtrace" = 1;
    "kernel.panic_print" = 127;
    "kernel.sysrq" = 1;
  };

  # Networking: DHCPv4 + IPv6 RA on `end0`, Google DNS, NTP, deterministic MAC address
  networking = {
    hostName = "caliptra-fpga";
    useDHCP = false;
    useNetworkd = true;
    firewall.enable = false;
    nameservers = [
      "8.8.8.8"
      "2001:4860:4860::6464"
      "2001:4860:4860::64"
    ];
    timeServers = [ "time.google.com" ];
  };

  systemd.network = {
    enable = true;
    networks."10-end0" = {
      matchConfig.Name = "end0";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;
      };
    };
  };

  systemd.services.set-mac-address = {
    description = "Set deterministic board-unique MAC address on end0 from SD Card CID";
    before = [
      "systemd-networkd.service"
      "network-pre.target"
    ];
    wants = [ "network-pre.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${setMacAddressScript}/bin/set-mac-address end0";
    };
  };

  services.timesyncd.enable = true;

  # SSH configuration (enabled with developer keys in `dev` mode)
  services.openssh = {
    enable = cfg.isDev;
    settings = {
      PubkeyAuthentication = true;
      PasswordAuthentication = false;
    };
  };

  # Users & passwordless sudo (`runner ALL=(ALL) NOPASSWD: SETENV: ALL`)
  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;
  users.users.runner = {
    isNormalUser = true;
    uid = 1000;
    home = "/home/runner";
    createHome = true;
    linger = true;
    shell = pkgs.bashInteractive;
    extraGroups = [
      "wheel"
      "dialout"
      "tty"
    ];
    openssh.authorizedKeys.keys = lib.optionals cfg.isDev sshKeys;
  };

  services.logind.settings.Login.RemoveIPC = false;

  security.sudo = {
    enable = true;
    wheelNeedsPassword = false;
    extraRules = [
      {
        users = [ "runner" ];
        commands = [
          {
            command = "ALL";
            options = [
              "NOPASSWD"
              "SETENV"
            ];
          }
        ];
      }
    ];
    extraConfig = ''
      Defaults env_keep += "NIX_LD NIX_LD_LIBRARY_PATH PATH"
    '';
  };

  # Enable `nix-ld` so unpatched Ubuntu/Debian aarch64 test binaries from `caliptra-builder`
  # and any downloaded tools execute natively without patchelf.
  programs.nix-ld = {
    enable = true;
    libraries = with pkgs; [
      stdenv.cc.cc
      zlib
      zstd
      openssl
      icu
      curl
      util-linux
      systemd
    ];
  };

  environment.variables = {
    NIX_LD = "/run/current-system/sw/share/nix-ld/lib/ld.so";
    NIX_LD_LIBRARY_PATH = "/run/current-system/sw/share/nix-ld/lib";
  };

  # Ensure standard FHS paths (`/lib/ld-linux-aarch64.so.1`, `/lib/firmware`, `/usr/bin/cargo-nextest`) exist
  systemd.tmpfiles.rules = [
    "d /lib/firmware 0755 root root -"
    "L+ /lib/ld-linux-aarch64.so.1 - - - - ${config.programs.nix-ld.package}/libexec/nix-ld"
    "L+ /usr/bin/cargo-nextest - - - - ${pkgs.cargo-nextest}/bin/cargo-nextest"
    "L+ /usr/bin/rsync - - - - ${pkgs.rsync}/bin/rsync"
    "L+ /usr/bin/podman - - - - ${podmanStub}/bin/podman"
    "L+ /home/runner/run.sh - - - - ${pkgs.github-runner}/bin/run.sh"
  ];

  # System packages matching `build.sh`
  environment.systemPackages =
    with pkgs;
    [
      git
      curl
      cacert
      sudo
      vmtouch
      fping
      openocd
      gdb
      macchanger
      cargo-nextest
      rsync
      jq
      kmod
      pciutils
      usbutils
      github-runner
      podmanStub
      setMacAddressScript
      startupScript
    ]
    ++ lib.optionals cfg.isDev [
      openssh
      tmux
      cloud-utils
      e2fsprogs
      resizeRootfsScript
    ];

  # Build metadata file `/etc/caliptra-build-info`
  environment.etc."caliptra-build-info".text = ''
    Build system: nixos-${config.system.nixos.release}
    Image env : ${if cfg.isDev then "dev" else "non-dev"}
    Image variant : ${cfg.variant}
    Runner version : ${pkgs.github-runner.version}
    Kernel source : nix-linux-xlnx
    Workflow name : ${cfg.workflowInfo.workflow}
    Workflow branch : ${cfg.workflowInfo.headRef}
    Workflow build commit : ${cfg.workflowInfo.workflowSha}
  '';

  # Disable default serial-getty on ttyAMA0 because `startup-script.service` owns `/dev/ttyAMA0`
  systemd.services."serial-getty@ttyAMA0".enable = false;

  # UART startup service for `fpga-boss`
  systemd.services.startup-script = {
    description = "Caliptra FPGA UART Startup Script (fpga-boss interface)";
    after = [
      "serial-getty.target"
      "time-sync.target"
      "network-online.target"
    ];
    wants = [
      "serial-getty.target"
      "time-sync.target"
      "network-online.target"
    ];
    conflicts = [ "serial-getty@ttyAMA0.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "idle";
      Restart = "no";
      StandardInput = "tty-force";
      StandardOutput = "tty";
      StandardError = "tty";
      TTYPath = "/dev/ttyAMA0";
      User = "root";
      WorkingDirectory = "/home/runner";
      ExecStart = "${startupScript}/bin/startup-script";
    };
  };

  # One-shot rootfs expansion service for `dev` images
  systemd.services.resize-rootfs = lib.mkIf cfg.isDev {
    description = "Resize root partition to fill SD card on first boot";
    after = [ "local-fs.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${resizeRootfsScript}/bin/resize-rootfs";
    };
  };

  # Keep Nix store footprint minimal on the FPGA image
  documentation.enable = false;
  documentation.man.enable = false;
  documentation.nixos.enable = false;
}
