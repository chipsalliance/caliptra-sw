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

### Requirements: ###
 - Vivado
   - `Version v2022.2`
 - FPGA
   - `ZCU104 Development Board`
   - https://www.xilinx.com/products/boards-and-kits/zcu104.html

### ZCU104 ###
#### Processing system one time setup: ####
1. Install ZCU104 SD card image
   - https://ubuntu.com/download/amd-xilinx
1. Configure SW6 to boot from SD1.
   - Mode SW6[4:1]: OFF, OFF, OFF, ON
     ![](./images/zynq_boot_switch.jpg)
1. Install rustup using Unix directions: https://rustup.rs/#

#### Helpful commands: ####
 - Disable CPU IDLE. Vivado HW Manager access during IDLE causes crashes.
   - `echo 1 > /sys/devices/system/cpu/cpu0/cpuidle/state1/disable`
   - `echo 1 > /sys/devices/system/cpu/cpu1/cpuidle/state1/disable`
   - `echo 1 > /sys/devices/system/cpu/cpu2/cpuidle/state1/disable`
   - `echo 1 > /sys/devices/system/cpu/cpu3/cpuidle/state1/disable`
 - Reduce fan speed.
   - https://support.xilinx.com/s/question/0D52E00006iHuopSAC/zcu104-fan-running-at-max-speed?language=en_US
   - `echo 321 > /sys/class/gpio/export`
   - `echo out > /sys/class/gpio/gpio321/direction`

#### Serial port configuration: ####
Serial port settings for connection over USB.
 - Speed: 115200
 - Data bits: 8
 - Stop bits: 1
 - Parity: None
 - Flow control: None

### FPGA build steps: ###
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
    - Generate Bitstream: `write_bitstream -bin_file \tmp\caliptra_fpga`

### Processing System - Programmable Logic interfaces ###
#### AXI Memory Map ####
 - SOC adapter for driving caliptra-top signals
   - 0x80000000 - Generic Input Wires
   - 0x80000008 - Generic Output Wires
   - 0x80000010-0x8000002C - Deobfuscation key (256 bit)
   - 0x80000030 - Control
     - `[0] -> cptra_pwrgood`
     - `[1] -> cptra_rst_b`
     - `[3:2] -> device_lifecycle`
     - `[4] -> debug_locked`
   - 0x80000034 - Status
     - `[0] <- cptra_error_fatal`
     - `[1] <- cptra_error_non_fatal`
     - `[2] <- ready_for_fuses`
     - `[3] <- ready_for_fw`
     - `[4] <- ready_for_runtime`
   - 0x80000038 - PAUSER
     - `[31:0] -> PAUSER to Caliptra APB`
   - 0x80001000 - Log FIFO data. Reads pop data from FIFO.
     - `[7:0] -> Next log character`
     - `[8] -> Log character valid`
   - 0x80001004 - Log FIFO register
     - `[0] -> Log FIFO empty`
     - `[1] -> Log FIFO full (probably overrun)`
   - 0x80001008 - ITRNG FIFO data. Write loads data to FIFO.
     - `[31:0] -> 32 bits of random data to be fed to itrng_data 4 bits at a time`
   - 0x8000100C - ITRNG FIFO status.
     - `[0] -> ITRNG FIFO empty`
     - `[1] -> ITRNG FIFO full`
     - `[2] -> ITRNG FIFO reset`
 - ROM Backdoor - 32K
   - `0x82000000 - 0x82007FFF`
 - Caliptra soc register interface
   - `0x90000000`
#### Interrupts ####
 - 89 - Log FIFO half full.

### Loading and execution Steps: ###
1. Install FPGA image
    - `sudo fpgautil -b caliptra_fpga_project_bd_wrapper.bin -f Full -n Full`
1. Insert kernel modules for IO access
    - As root:
      - `cd hw-latest/fpga/rom_backdoor`
      - `make`
      - `insmod rom_backdoor.ko`
      - `cd hw-latest/fpga/io_module`
      - `make`
      - `insmod io_module.ko`
      - `chmod 666 /dev/uio4`
1. Set FPGA PLL frequency
    - As root:
      - `echo 20000000 > /sys/bus/platform/drivers/xilinx_fclk/fclk0/set_rate`
1. Execute test targeting fpga_realtime
    - `CPTRA_UIO_NUM=4 cargo test -p caliptra-test --features=fpga_realtime smoke_test`

### JTAG debug
Requirements:
- Security state must have either debug_locked == false or lifecycle == manuf.
- Set "debug = true" in firmware profile to provide line information to GDB.
- Olimex ARM-USB-TINY-H with SiFive-Arty Adapter

#### PMOD pin assignment ####
![](./images/Caliptra_FPGA_PMOD_JTAG.svg)

#### Debugger launch procedure ####
1. Invoke OpenOCD server
    - `openocd.exe -f ~/openocd_caliptra.txt`
1. Connect client(s) for debug
    - GDB: Port 3333
    - Telnet: Port 4444

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
