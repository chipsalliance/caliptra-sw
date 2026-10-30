# Licensed under the Apache-2.0 license
#
# Builds the Xilinx Versal Linux kernel (`linux-xlnx`) and U-Boot `boot.scr`.

{
  pkgs,
  lib,
}:

let
  # Exact commit built by PetaLinux 2024.2 (`Linux version 6.6.40-xilinx-g2b7f6f70a62a`)
  linuxXlnxVersion = "6.6.40";
  linuxXlnxRev = "2b7f6f70a62a52a467bed030a27c2ada879106e9";

  linuxXlnx = pkgs.buildLinux {
    pname = "linux-xlnx-vck190";
    version = linuxXlnxVersion;
    modDirVersion = linuxXlnxVersion;

    src = pkgs.fetchFromGitHub {
      owner = "Xilinx";
      repo = "linux-xlnx";
      rev = linuxXlnxRev;
      hash = "sha256-jI6/r28vhalSqOOq5/cMTcZdzyXOAwBeUV3eWKrsDUs=";
    };

    defconfig = "xilinx_defconfig";
    enableCommonConfig = false;
    autoModules = false;
    ignoreConfigErrors = true;

    structuredExtraConfig =
      with lib.kernel;
      lib.mapAttrs (_: lib.mkForce) {
        # Watchdog Configuration (from caliptra.cfg)
        WATCHDOG = yes;
        CADENCE_WATCHDOG = yes;
        XILINX_WATCHDOG = yes;
        SOFT_WATCHDOG = yes;
        WATCHDOG_NOWAYOUT = yes;

        # OverlayFS and Tmpfs Configuration
        OVERLAY_FS = yes;
        OVERLAY_FS_REDIRECT_DIR = yes;
        OVERLAY_FS_INDEX = yes;
        OVERLAY_FS_XINO_AUTO = yes;
        OVERLAY_FS_METACOPY = yes;
        OVERLAY_FS_DEBUG = yes;
        OVERLAY_FS_NFS_EXPORT = no;
        TMPFS = yes;
        TMPFS_POSIX_ACL = yes;
        BLK_DEV_INITRD = yes;

        # SquashFS Configuration
        SQUASHFS = yes;
        SQUASHFS_FILE_CACHE = yes;
        SQUASHFS_FILE_DIRECT = no;
        SQUASHFS_DECOMP_SINGLE = yes;
        SQUASHFS_COMPILE_DECOMP_SINGLE = yes;
        SQUASHFS_XATTR = yes;
        SQUASHFS_ZLIB = yes;
        SQUASHFS_XZ = yes;
        SQUASHFS_ZSTD = yes;
        SQUASHFS_FRAGMENT_CACHE_SIZE = freeform "3";

        # UIO & FPGA Manager Drivers
        UIO = yes;
        UIO_PDRV_GENIRQ = yes;
        UIO_DMEM_GENIRQ = yes;
        FPGA = yes;
        FPGA_MGR_VERSAL_FPGA = yes;

        # Debugging & GPIO sysfs (for OpenOCD EMIO JTAG)
        IKHEADERS = yes;
        MODULE_DEBUG = yes;
        MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS = yes;
        GPIO_SYSFS = yes;
        DEBUG_USER = yes;

        # Forced Kernel Command Line matching caliptra.cfg
        CMDLINE = freeform "earlycon=pl011,mmio32,0xFF000000,115200n8 root=/dev/mmcblk0p3 ro rootwait console=ttyAMA0,115200 console=tty1 init=/usr/sbin/overlay-mount.sh loglevel=7 panic=10 clk_ignore_unused";
        CMDLINE_FORCE = yes;
      };

    extraMeta = {
      description = "Linux kernel for AMD/Xilinx Versal VCK-190 FPGA";
      platforms = [ "aarch64-linux" ];
    };
  };

  # U-Boot script (boot.scr) matching PetaLinux Versal SD boot flow
  bootCmd = pkgs.writeText "boot.cmd" ''
    setenv bootargs "earlycon=pl011,mmio32,0xFF000000,115200n8 root=/dev/mmcblk0p3 ro rootwait console=ttyAMA0,115200 console=tty1 init=/usr/sbin/overlay-mount.sh loglevel=7 panic=10 clk_ignore_unused"
    for boot_target in ''${boot_targets}; do
      if test "''${boot_target}" = "mmc0" || test "''${boot_target}" = "mmc1"; then
        if test -e ''${devtype} ''${devnum}:''${distro_bootpart} /image.ub; then
          fatload ''${devtype} ''${devnum}:''${distro_bootpart} 0x10000000 image.ub;
          bootm 0x10000000;
        fi
        if test -e ''${devtype} ''${devnum}:''${distro_bootpart} /Image; then
          fatload ''${devtype} ''${devnum}:''${distro_bootpart} 0x00200000 Image;
        fi
        if test -e ''${devtype} ''${devnum}:''${distro_bootpart} /system.dtb; then
          fatload ''${devtype} ''${devnum}:''${distro_bootpart} 0x00001000 system.dtb;
          setenv fdtcontroladdr 0x00001000;
        fi
        booti 0x00200000 - ''${fdtcontroladdr};
      fi
    done
  '';

  bootScr = pkgs.runCommand "vck190-boot-scr" {
    nativeBuildInputs = [ pkgs.buildPackages.ubootTools ];
  } ''
    mkimage -c none -A arm64 -T script -d ${bootCmd} $out
  '';
in
{
  inherit linuxXlnx bootScr;
}
