_*SPDX-License-Identifier: Apache-2.0<BR>
<BR>
<BR>
Licensed under the Apache License, Version 2.0 (the "License");<BR>
you may not use this file except in compliance with the License.<BR>
You may obtain a copy of the License at<BR>
<BR>
http://www.apache.org/licenses/LICENSE-2.0 <BR>
<BR>
Unless required by applicable law or agreed to in writing, software<BR>
distributed under the License is distributed on an "AS IS" BASIS,<BR>
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.<BR>
See the License for the specific language governing permissions and<BR>
limitations under the License.*_<BR>

# **Caliptra FPGA Guide** #
FPGA provides a fast environment for software development and testing that uses Caliptra RTL.
The FPGA's Programmable Logic is programmed with the Caliptra RTL and FPGA specific SoC wrapper logic including a connection to the Processing System AXI bus.
The Processing System ARM cores then act as the SoC Security Processor with memory mapped access to Caliptra's public register space.

![](./images/fpga_module_diagram.svg)

### Requirements: ###
 - Vivado
   - Version v2022.2 or 2024.2
 - PetaLinux Tools
   - Version must match Vivado
 - FPGA
   - [VCK190](https://www.xilinx.com/products/boards-and-kits/vck190.html)
   - VMK180 will be supported soon.

### Versal ###
#### Processing system one time setup: ####
1. Download VCK190 SD card image and install to a microSD card.
   - Insert the SD card into the slot on top of the board. The slot below the board is for the System Controller.
   - https://ubuntu.com/download/amd-xilinx
1. Configure SW1 to boot from SD1: [Image](./images/versal_boot_switch.jpg)
   - Mode SW1[4:1]: OFF, OFF, OFF, ON
1. Boot from the SD card. (Suggest using the serial port for initial setup)
   - Initial credentials
     - User: ubuntu Pass: ubuntu
   - Install software dependencies - *Do not update the system*
     ```shell
     sudo apt update
     sudo apt install make gcc
     ```
   - Install rustup using Unix directions: https://rustup.rs/#
   - Consider assigning a hostname for SSH access.

#### Serial port configuration: ####
The USB Type-C connecter J207 provides UART and JTAG access to the board. The first UART connection should be for the PS.

Serial port settings:
 - Speed: 115200
 - Data bits: 8
 - Stop bits: 1
 - Parity: None
 - Flow control: None

### FPGA build steps: ###
The FPGA build process uses Vivado's batch mode to procedurally create the Vivado project using fpga_configuration.tcl.
This script provides a number of configuration options for features that can be enabled using "-tclargs OPTION=VALUE OPTION=VALUE"

| Option      | Purpose
| ------      | -------
| BUILD       | Automatically start building the FPGA.
| GUI         | Open the Vivado GUI.
| JTAG        | Assign JTAG signals to PS GPIO.
| ITRNG       | Enable Caliptra's ITRNG.
| CG_EN       | Removes FPGA optimizations and allows clock gating.
| RTL_VERSION | RTL directory under hw/. latest or 1.0.
| BOARD       | VCK190 or VMK180 (TODO: VMK180 not fully enabled)

 - Build FPGA image without GUI
    - `vivado -mode batch -source fpga_configuration.tcl -tclargs BUILD=TRUE`
    - Above command creates a bitstream located at: caliptra_build/caliptra_fpga.bin
    - To check the git revision a bitstream was generated with
      - `xxd -s 0x88 -l 8 caliptra_build/caliptra_fpga.bin`
      - Result should be `3001 a001 xxxx xxxx`. 3001 a001 is a command to write the USR_ACCESS register and the rest is the hash.
 - Launch Vivado with GUI
    - `vivado -mode batch -source fpga_configuration.tcl -tclargs GUI=TRUE`
    - Run Synthesis: `launch_runs synth_1`
    - [Optional] Set Up Debug signals on Synthesized Design
    - Run Implementation: `launch_runs impl_1`
    - Generate Device Image: `write_device_image $outputDir/caliptra_fpga`
    - Export hardware: `write_hw_platform -fixed -include_bit -force -file $outputDir/caliptra_fpga.xsa`

### Build boot.bin: ###
 - Source PetaLinux tools from the PetaLinux installation directory.
   `source settings.sh`
 - Run steps from [create_boot_bin.sh](create_boot_bin.sh) to create a BOOT.BIN
   - `./create_boot_bin.sh /path/to/caliptra_fpga_project_bd_wrapper.xsa`
 - Copy petalinux_project/images/linux/BOOT.BIN to the boot partition as boot1900.bin
   - If the Ubuntu image is booted, it will mount the boot partition at /boot/firmware/
   - If boot1900.bin fails to boot the system will fallback to the default boot1901.bin

### Running Caliptra tests from the FPGA: ###
```shell
# Install dependencies
sudo apt update
sudo apt install make gcc
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Clone this repo
git clone https://github.com/chipsalliance/caliptra-sw.git
git submodule init
git submodule update
# Compile and install the kernel module
sudo ./hw/fpga/setup_fpga.sh

CPTRA_UIO_NUM=0 cargo test --features=fpga_realtime,itrng -p caliptra-test smoke_test::smoke_test
```

### Processing System - Programmable Logic interfaces ###
[FPGA Wrapper Registers](fpga_wrapper_regs.md)

#### Versal Memory Map ####
| IP/Peripheral                       | Address size | Start address | End address |
| :---------------------------------- | :----------- | :------------ | :---------- |
| ROM Backdoor                        | 96 KiB       | 0xB000_0000   | 0xB001_7FFF |
| FPGA Wrapper Registers              | 8 KiB        | 0xA401_0000   | 0xA401_1FFF |
| Caliptra                            | 1 MiB        | 0xA410_0000   | 0xA41F_FFFF |

### JTAG debug
Requirements:
- Security state must have either debug_locked == false or lifecycle == manuf.
- Set "debug = true" in firmware profile to provide line information to GDB.
- openocd 0.12.0 (must be configured with --enable-sysfsgpio)
- gdb-multiarch

#### Debugger launch procedure ####
Caliptra's JTAG pins are directly connected to EMIO GPIO pins bridging the PS and PL. OpenOCD is run on the ARM core and uses SysFs to interface with the GPIO pins.
1. Invoke OpenOCD server
    - `sudo openocd --file caliptra-sw/hw/fpga/openocd_caliptra.txt`
1. Connect client(s) for debug
    - GDB: `gdb-multiarch [bin] -ex 'target remote localhost:3333'`
    - Telnet: `telnet localhost 4444`

#### Caliptra SoC interface registers ####
Over Telnet connection to OpenOCD: `riscv.cpu riscv dmi_read [addr]`

#### JTAG testing ####
Test requirements for both OpenOCD and GDB:
- JTAG port is accessible when debug_locked == true or lifecycle == manufacturing. The port is inaccessible otherwise.
- Read access to ROM space using 8, 16, 32, and 64 bit reads.
- Read and write access to DCCM using 8, 16, 32, and 64 bit accesses.
- Access to ICCM using 32 and 64 bit reads, 32 bit writes.
- Access to VEER core registers.
- HW and SW breakpoints halt the CPU.
- Watchpoints on DCCM and Caliptra register access halt the CPU.
 
Test requirements exclusive to GDB:
- Basic commands all work (step, next, frame, info, bt, ni, si, etc.).
 
Test requirements exclusive to OpenOCD:
- Basic commands all work (reg, step, resume, etc.).
- Access to VEER CSRs.
- Access to Debug Module registers.
- Caliptra registers exposed to JTAG RW/RO status matches.
