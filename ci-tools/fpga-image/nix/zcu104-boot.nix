# Licensed under the Apache-2.0 license
#
# ZCU104 (Caliptra 1.x) boot firmware & kernel modules bundle.
#
# Fetches the Canonical Xilinx ZCU Ubuntu 22.04 system-boot archive used by
# Caliptra 1.x (`boot1041.bin`, `image.fit` with kernel `5.15.0-1015-xilinx-zynqmp`),
# extracts its kernel module tree for NixOS (`kmod`/`systemd-udevd`), and compiles
# `boot.scr.uimg` to boot into NixOS stage-2 init.

{
  buildPkgs,
  lib ? buildPkgs.lib,
}:

let
  systemBootTarball = buildPkgs.fetchurl {
    url = "https://people.canonical.com/~platform/images/xilinx/zcu-ubuntu-22.04/iot-limerick-zcu-classic-desktop-2204-x05-2-20221123-58-system-boot.tar.gz";
    sha256 = "714cc0b12607c476672f569b3f996ce8b3446bd05b30bffcd1c772c483923098";
  };

  kernelModules =
    buildPkgs.runCommand "zcu104-kernel-modules-5.15.0-1015-xilinx-zynqmp"
      {
        nativeBuildInputs = with buildPkgs; [
          gnutar
          gzip
          ubootTools
          zstd
          cpio
        ];
      }
      ''
        mkdir -p work/ramdisk $out/lib
        tar -xzf ${systemBootTarball} -C work ./image.fit
        dumpimage -T flat_dt -p 1 -o work/ramdisk.img work/image.fit
        (
          cd work/ramdisk
          zstd -d -c ../ramdisk.img | cpio -idmu "usr/lib/modules/*" 2>/dev/null || true
        )
        cp -r work/ramdisk/usr/lib/modules $out/lib/modules
      '';

  mkBootScrUimg =
    {
      isDev,
      toplevel,
    }:
    let
      overlayArg = lib.optionalString (!isDev) "overlayroot=tmpfs ";
      bootCmd = buildPkgs.writeText "zcu104-boot.scr.cmd" ''
        setenv bootargs "earlycon root=/dev/mmcblk0p3 rootwait console=ttyPS0,115200 console=tty1 uio_pdrv_genirq.of_id=generic-uio cma=700M ${overlayArg}modprobe.blacklist=zynqmp_dpsub,i2c_mux_pca954x,i2c_cadence,ahci_ceva,raid10,raid1,raid0,raid456 init=${toplevel}/init"
        load mmc 0:1 0x10000000 image.fit
        bootm 0x10000000 0x10000000 $fdtcontroladdr
      '';
    in
    buildPkgs.runCommand "zcu104-boot.scr.uimg"
      {
        nativeBuildInputs = [ buildPkgs.ubootTools ];
      }
      ''
        mkimage -T script -n "boot script" -C none -d ${bootCmd} $out
      '';
in
{
  inherit
    systemBootTarball
    kernelModules
    mkBootScrUimg
    ;
}
