# `caliptra_fpga_hcd` Linux USB 2.0 Host Controller Driver

`caliptra_fpga_hcd.ko` registers the Caliptra 2.2 FPGA wrapper's in-fabric
USB 2.0 High-Speed ULPI host engine (`caliptra_fpga_ulpi_host`, default physical
base `0xA401_4000`) as a single-port High-Speed USB 2.0 root hub under Linux
`usbcore`.

With this module loaded after programming a USB-enabled segmented bitstream:
- Linux `usbcore` performs VBUS attach, High-Speed bus reset + Chirp handshake,
  and standard Chapter 9 enumeration automatically.
- Standard userspace USB tools (`lsusb`, `libusb`, `usbmon`) and
  `caliptra-mcu-usb-recovery` interact with the emulated Caliptra 2.2 USB device
  identically to physical silicon.

## FPGA SD Image Packaging

`hw/fpga/create_boot_bin.sh` builds `caliptra_fpga_hcd.ko` via PetaLinux
(`recipes-modules/caliptra-fpga-hcd`), and `ci-tools/fpga-image/build.sh`
installs it at `/home/runner/caliptra_fpga_hcd.ko` alongside
`/home/runner/io-module.ko`.

> **Note:** Unlike `io-module.ko`, `caliptra_fpga_hcd.ko` is **not** loaded at OS
> boot by `startup-script.sh`. Its root-hub status timer polls `0xA401_4008`
> every 100 ms, so `ModelFpgaRealtime` loads the module on demand after
> verifying a USB-capable bitstream is programmed and unloads it across AXI
> resets and bitstream reloads.

## Standalone Cross-Compilation

To cross-compile `caliptra_fpga_hcd.ko` manually against an out-of-tree VCK-190
kernel build directory:

```shell
cd hw/fpga/caliptra_fpga_hcd
make KDIR=/path/to/vck190-kbuild ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
```
