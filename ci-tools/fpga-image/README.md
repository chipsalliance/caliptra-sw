# Caliptra FPGA SD Card Image

This directory contains the Nix build definition (`flake.nix`) for the Caliptra FPGA SD card images across both AMD/Xilinx Versal VCK-190 (Caliptra 2.x `core` and `subsystem` variants) and AMD/Xilinx ZynqMP ZCU104 (Caliptra 1.x `zcu104` target), in both `ci` and `dev` flavors.

## Overview

Every component of the SD card image is built reproducibly in Nix without requiring PetaLinux, XSCT, `sudo`, `losetup`, `chroot`, or `debootstrap`:

- **`nix/boot-firmware.nix`** (VCK-190 `core` & `subsystem`):
  - `bootgen`: Open-source Xilinx Bootgen (`xilinx_v2024.2`) built natively on the host.
  - `system.dtb`: Device tree blob compiled from `nix/system.dts` via `dtc` (with `sbsa-uart` and `versal-gpio` patches).
  - `arm-trusted-firmware`: `bl31.elf` for Versal (`xlnx_rebase_v2.10_2024.2`, `PLAT=versal`, `VERSAL_CONSOLE=pl011`).
  - `u-boot-xlnx`: `u-boot.elf` for Versal (`xlnx_rebase_v2024.01_2024.2`, `xilinx_versal_virt_defconfig` + Cadence watchdog).
  - `BOOT.BIN`: Assembled directly from the variant's Vivado `.xsa` archive (`*_boot.pdi`, `plm.elf`, `psm_fw.elf`) + `system.dtb` + `bl31.elf` + `u-boot.elf` using `bootgen -arch versal`.
- **`nix/kernel.nix`** (VCK-190 `core` & `subsystem`):
  - `linux-xlnx`: Cross-compiled `github:Xilinx/linux-xlnx` (`6.6.40-xilinx-g2b7f6f70a62a`, `xlnx_rebase_v6.6_LTS_2024.2`) with `xilinx_defconfig` + `caliptra.cfg` Kconfig fragments.
  - `boot.scr`: U-Boot boot script image built via `mkimage`.
- **`nix/io-module.nix`** (VCK-190 `core` & `subsystem`):
  - Out-of-tree Caliptra UIO kernel module (`io-module.ko`) compiled against `linux-xlnx` for either `core` (`nix/io-module/io_module.c`) or `subsystem` (`nix/io-module/mcu_io_module.c`).
- **`nix/zcu104-boot.nix`** (ZCU104 `1.x`):
  - Fetches Canonical's Xilinx ZCU Ubuntu 22.04 `system-boot.tar.gz` (`boot1041.bin`, `image.fit` with kernel `5.15.0-1015-xilinx-zynqmp`), extracts `/lib/modules/5.15.0-1015-xilinx-zynqmp` from the FIT initramfs for NixOS, and compiles `boot.scr.uimg` with `init=${toplevel}/init` (`overlayroot=tmpfs` in `ci` mode) on `ttyPS0,115200`.
- **`nix/configuration.nix` & `nix/sd-image.nix`**:
  - Declarative NixOS `aarch64-linux` rootfs (`systemd-networkd` DHCPv4/IPv6 on `end0`, deterministic SD CID MAC address service, `nix-ld` dynamic loader compatibility for unpatched Ubuntu/Debian `aarch64` test binaries, `github-runner`, `cargo-nextest`, `openocd` with `sysfsgpio`, `gdb`, and `startup-script.service` emitting `fpga-boss` UART sentinels on `/dev/ttyAMA0` for VCK-190 or `/dev/ttyPS0` for ZCU104).
  - Rootless MBR image assembly (`p1` FAT32 boot, `p2` `CONFIG_PARTITION` sentinel, `p3` read-only zstd SquashFS + tmpfs overlay for `ci` or mutable auto-resized `ext4` for `dev`).

### Building Images

```bash
cd ci-tools/fpga-image

# Build CI image (SquashFS + tmpfs overlay) for VCK-190 (Subsystem / Core) or ZCU104 (1.x)
nix build path:.#vck190-subsystem-ci
nix build path:.#vck190-core-ci
nix build path:.#zcu104-ci

# Build Developer image (mutable ext4 + SSH keys + auto-resize) for VCK-190 or ZCU104
nix build path:.#vck190-subsystem-dev
nix build path:.#vck190-core-dev
nix build path:.#zcu104-dev

# Build individual boot/kernel artifacts
nix build path:.#boot-bin-subsystem
nix build path:.#boot-bin-core
nix build path:.#linux-xlnx
nix build path:.#io-module-subsystem
nix build path:.#io-module-core
nix build path:.#zcu104-kernel-modules
```
