# Licensed under the Apache-2.0 license
#
# Rootless VCK-190 SD Card Image Builder for NixOS.
#
# Produces an MBR-partitioned disk image matching the exact layout required by
# the VCK-190 kernel command line (`root=/dev/mmcblk0p3 init=/usr/sbin/overlay-mount.sh`)
# and `fpga-boss`:
#   - p1: FAT32 bootable partition (320,000 sectors = ~156 MiB) containing
#         BOOT.BIN, system.dtb, boot.scr, and Image (all built in Nix)
#   - p2: 8-sector partition containing the `CONFIG_PARTITION` sentinel
#   - p3: Root filesystem:
#         * `ci` mode: zstd-compressed read-only SquashFS + tmpfs overlay at boot
#         * `dev` mode: mutable ext4 filesystem expanded to fill the SD card on first boot
#   - p4: (CI partition table entry only) persistent partition entry

{
  config,
  lib,
  pkgs,
  buildPkgs ? pkgs.buildPackages,
  targetPkgs ? (
    if buildPkgs.stdenv.hostPlatform.system == "aarch64-linux" then
      pkgs
    else
      buildPkgs.pkgsCross.aarch64-multiplatform
  ),
  ...
}:

let
  cfg = config.vck190;
  toplevel = config.system.build.toplevel;

  vck190BootFirmware = import ./boot-firmware.nix {
    inherit buildPkgs targetPkgs;
    inherit (buildPkgs) lib;
  };

  vck190KernelBundle = import ./kernel.nix {
    pkgs = targetPkgs;
    inherit (targetPkgs) lib;
  };

  bootBin = vck190BootFirmware.mkBootBin (
    {
      variant = cfg.variant;
    }
    // lib.optionalAttrs (cfg.xsa != null) {
      xsa = cfg.xsa;
    }
  );

  # NixOS-compatible `/usr/sbin/overlay-mount.sh` executed as PID 1 by the
  # VCK-190 kernel (`init=/usr/sbin/overlay-mount.sh`).
  # Sets up the tmpfs overlay (in CI mode) or remounts `/` rw (in Dev mode),
  # then hands off to NixOS stage-2 init (`${toplevel}/init`).
  overlayMountScript = pkgs.writeScript "overlay-mount.sh" ''
    #!${pkgs.bashInteractive}/bin/sh
    # Licensed under the Apache-2.0 license

    export PATH=${
      lib.makeBinPath [
        pkgs.util-linux
        pkgs.coreutils
        pkgs.bashInteractive
      ]
    }:/sbin:/bin:/usr/sbin:/usr/bin

    LOG_FILE="/run/overlay-mount.log"

    echo "--- Starting Caliptra NixOS Overlay Mount Script ---"

    mkdir -p /proc /sys /dev /run /mnt/root_base /mnt/root_overlay /mnt/new_root

    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    mkdir -p /dev/pts /dev/shm
    mount -t devpts devpts /dev/pts
    mount -t tmpfs tmpfs /dev/shm
    mount -t tmpfs tmpfs /run

    # Developer mode: skip overlayfs and boot mutable ext4 root directly
    if [ -f /etc/no_overlayfs ]; then
      echo "Developer mode detected. Skipping overlay."
      mount -o rw,remount /
      exec ${toplevel}/init
    fi

    echo "Starting Overlay Mount Script..." > "''${LOG_FILE}"

    echo "Mounting lower layer..." | tee -a "''${LOG_FILE}"
    mount --bind / /mnt/root_base

    echo "Creating writable upper layer (tmpfs)..." | tee -a "''${LOG_FILE}"
    mount -t tmpfs tmpfs /mnt/root_overlay
    mkdir -p /mnt/root_overlay/upper /mnt/root_overlay/work

    echo "Assembling overlayfs..." | tee -a "''${LOG_FILE}"
    mount -t overlay overlay \
      -o lowerdir=/mnt/root_base,upperdir=/mnt/root_overlay/upper,workdir=/mnt/root_overlay/work \
      /mnt/new_root

    echo "Moving virtual filesystems..." | tee -a "''${LOG_FILE}"
    mount --move /dev /mnt/new_root/dev
    mount --move /proc /mnt/new_root/proc
    mount --move /sys /mnt/new_root/sys
    mount --move /run /mnt/new_root/run

    echo "Switching to overlay root and starting NixOS stage-2 init..." | tee -a "''${LOG_FILE}"
    cd /mnt/new_root
    mkdir -p old_root
    if ! pivot_root . old_root; then
      echo "pivot_root failed! Dropping to shell."
      exec ${pkgs.bashInteractive}/bin/sh
    fi

    exec ${toplevel}/init || {
      echo "Failed to exec NixOS stage-2 init! Dropping to shell."
      exec ${pkgs.bashInteractive}/bin/sh
    }
  '';

  sdClosureInfo = buildPkgs.closureInfo {
    rootPaths = [
      toplevel
      overlayMountScript
    ];
  };

  # Builds the partition 3 rootfs image (SquashFS for `ci`, ext4 for `dev`)
  # using native host tools (`buildPkgs`) for fast image creation.
  rootfsImage = buildPkgs.stdenv.mkDerivation {
    name = "vck190-${cfg.variant}-${if cfg.isDev then "dev-ext4" else "ci-squashfs"}.img";

    nativeBuildInputs = with buildPkgs; [
      coreutils
      findutils
      gnutar
      gzip
      squashfsTools
      e2fsprogs
      libfaketime
      fakeroot
    ];

    buildCommand = ''
      mkdir -p ./rootImage/nix/store
      mkdir -p ./rootImage/bin ./rootImage/sbin ./rootImage/usr/bin ./rootImage/usr/sbin
      mkdir -p ./rootImage/etc ./rootImage/proc ./rootImage/sys ./rootImage/dev ./rootImage/run
      mkdir -p ./rootImage/tmp ./rootImage/var ./rootImage/lib/firmware
      mkdir -p ./rootImage/mnt/root_base ./rootImage/mnt/root_overlay ./rootImage/mnt/new_root
      mkdir -p ./rootImage/home/runner

      echo "Copying Nix store closure into rootImage..."
      xargs -I % cp -a --reflink=auto % -t ./rootImage/nix/store/ < ${sdClosureInfo}/store-paths
      cp ${sdClosureInfo}/registration ./rootImage/nix-path-registration

      # Bootstrap symlinks needed before NixOS stage-2 activation runs
      ln -sf ${pkgs.bashInteractive}/bin/sh ./rootImage/bin/sh
      ln -sf ${pkgs.bashInteractive}/bin/bash ./rootImage/bin/bash
      ln -sf ${pkgs.coreutils}/bin/env ./rootImage/usr/bin/env
      ln -sf ${toplevel}/init ./rootImage/sbin/init

      # Install overlay-mount.sh at /usr/sbin/overlay-mount.sh
      cp ${overlayMountScript} ./rootImage/usr/sbin/overlay-mount.sh
      chmod 0755 ./rootImage/usr/sbin/overlay-mount.sh

      # Link GitHub Actions runner entrypoint at /home/runner/run.sh
      ln -sf ${pkgs.github-runner}/bin/run.sh ./rootImage/home/runner/run.sh

      ${lib.optionalString cfg.isDev ''
        touch ./rootImage/etc/no_overlayfs
      ''}

      ${
        if cfg.isDev then
          ''
            # Dev image: allocate ~2 GiB ext4 partition (4,194,304 512B sectors) or larger if closure requires it
            minBytes=$((4194304 * 512))
            numInodes=$(find ./rootImage | wc -l)
            numDataBlocks=$(du -s -c -B 4096 --apparent-size ./rootImage | tail -1 | awk '{ print int($1 * 1.25) }')
            calcBytes=$((2 * 4096 * $numInodes + 4096 * $numDataBlocks))
            if (( calcBytes > minBytes )); then
              bytes=$calcBytes
            else
              bytes=$minBytes
            fi
            mebibyte=$((1024 * 1024))
            if (( bytes % mebibyte )); then
              bytes=$(( (bytes / mebibyte + 1) * mebibyte ))
            fi
            echo "Building ext4 dev rootfs of $bytes bytes..."
            truncate -s $bytes $out
            faketime -f "1970-01-01 00:00:01" fakeroot mkfs.ext4 -F -L NIXOS_ROOT -d ./rootImage $out
          ''
        else
          ''
            echo "Building zstd-compressed SquashFS CI rootfs..."
            SOURCE_DATE_EPOCH=0 mksquashfs ./rootImage $out \
              -comp zstd -all-root -no-strip -b 1048576 \
              -processors $NIX_BUILD_CORES -root-mode 0755
          ''
      }
    '';
  };

  # Assembles the complete partitioned SD card `.img` file without root/losetup
  sdImage = buildPkgs.stdenv.mkDerivation {
    name = "caliptra-fpga-image-${cfg.variant}${lib.optionalString cfg.isDev "-dev"}.img";

    nativeBuildInputs = with buildPkgs; [
      coreutils
      dosfstools
      mtools
      libfaketime
      util-linux
    ];

    buildCommand = ''
      mkdir -p $out
      img="$out/${if cfg.isDev then "dev-image.img" else "image.img"}"

      bootfs_blocks=$((80000 * 4))
      rootfs_bytes=$(stat --printf="%s" ${rootfsImage})
      rootfs_blocks=$(( (rootfs_bytes + 511) / 512 ))
      total_blocks=$((2048 + 8 + bootfs_blocks + rootfs_blocks))

      truncate -s $((total_blocks * 512)) "$img"

      ${
        if cfg.isDev then
          ''
            sfdisk --no-reread --no-tell-kernel "$img" <<EOF
            label: dos
            label-id: 0x4effe30a
            unit: sectors
            sector-size: 512

            p1 : start=2048, size=''${bootfs_blocks}, type=c, bootable
            p2 : start=$((2048 + bootfs_blocks)), size=8, type=83
            p3 : start=$((2048 + 8 + bootfs_blocks)), size=''${rootfs_blocks}, type=83
            EOF
          ''
        else
          ''
            persistfs_blocks=14680064
            truncate -s $(( (total_blocks + persistfs_blocks) * 512 )) "$img"
            sfdisk --no-reread --no-tell-kernel "$img" <<EOF
            label: dos
            label-id: 0x4effe30a
            unit: sectors
            sector-size: 512

            p1 : start=2048, size=''${bootfs_blocks}, type=c, bootable
            p2 : start=$((2048 + bootfs_blocks)), size=8, type=83
            p3 : start=$((2048 + 8 + bootfs_blocks)), size=''${rootfs_blocks}, type=83
            p4 : start=$((2048 + 8 + bootfs_blocks + rootfs_blocks)), size=''${persistfs_blocks}, type=83
            EOF
            # Truncate image right after p3 while keeping p4 in the MBR partition table
            truncate -s $((total_blocks * 512)) "$img"
          ''
      }

      # Build and populate FAT32 boot partition (p1)
      truncate -s $((bootfs_blocks * 512)) bootfs.img
      mkfs.vfat --invariant -i 4effe30a -n BOOT bootfs.img

      mkdir -p boot_files
      cp ${bootBin} boot_files/BOOT.BIN
      cp ${vck190BootFirmware.systemDtb} boot_files/system.dtb
      cp ${vck190KernelBundle.bootScr} boot_files/boot.scr
      cp ${vck190KernelBundle.linuxXlnx}/Image boot_files/Image

      find boot_files -exec touch --date=2000-01-01 {} +
      (
        cd boot_files
        for f in $(find . -type f | sort); do
          mcopy -pvm -i ../bootfs.img "$f" "::/$f"
        done
      )
      fsck.vfat -vn bootfs.img
      dd conv=notrunc if=bootfs.img of="$img" bs=512 seek=2048 count=$bootfs_blocks

      # Write CONFIG_PARTITION sentinel to p2
      printf "CONFIG_PARTITION\n" > config_part.bin
      dd conv=notrunc if=config_part.bin of="$img" bs=512 seek=$((2048 + bootfs_blocks))

      # Write RootFS image to p3
      dd conv=notrunc if=${rootfsImage} of="$img" bs=512 seek=$((2048 + 8 + bootfs_blocks))

      # Expose hydra build products for CI
      mkdir -p $out/nix-support
      echo "file sd-image $img" >> $out/nix-support/hydra-build-products
    '';
  };
in
{
  options.vck190 = {
    variant = lib.mkOption {
      type = lib.types.enum [
        "core"
        "subsystem"
      ];
      default = "subsystem";
      description = "Caliptra FPGA bitstream/UIO variant (`core` or `subsystem`).";
    };

    isDev = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to build a mutable developer image (`true`) or an immutable SquashFS+overlay CI image (`false`).";
    };

    xsa = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Optional override path to a custom Vivado `.xsa` archive for assembling `BOOT.BIN`.
        When `null`, defaults to the pinned CI `.xsa` for `vck190.variant`.
      '';
    };

    workflowInfo = {
      workflow = lib.mkOption {
        type = lib.types.str;
        default = "nix-flake";
      };
      headRef = lib.mkOption {
        type = lib.types.str;
        default = "main";
      };
      workflowSha = lib.mkOption {
        type = lib.types.str;
        default = "unknown";
      };
    };
  };

  config = {
    system.build.rootfsImage = rootfsImage;
    system.build.sdImage = sdImage;
  };
}
