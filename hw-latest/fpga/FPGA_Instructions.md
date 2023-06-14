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
 - [Not fully enabled] JTAG debugger
   - `Olimex ARM-USB-TINY-H`

### ZCU104 Processing System Setup: ###
This guide assumes that Ubuntu is installed on the MicroSD card and boots.
#### Booting ####
SD Card image: https://ubuntu.com/download/amd-xilinx

To boot SW6 needs to be configured to SD1.
- Mode SW6[4:1]: OFF, OFF, OFF, ON

#### Serial port configuration ####
The system can be accessed over SSH or using a USB-serial connection.
 - Speed: 115200
 - Data bits: 8
 - Stop bits: 1
 - Parity: None
 - Flow control: None

### FPGA Build Steps: ###
1. Launch Vivado with tcl script defining FPGA build
    - `vivado -mode batch -source vivado_create_caliptra_package.tcl`
1. Run Synthesis
    - Use GUI or: `launch_runs synth_1`
1. Set Up Debug signals on Synthesized Design
1. Run Implementation and generate bitstream
    - Use GUI or: `launch_runs impl_1`
1. FPGA image location:
    - `caliptra_build/caliptra_tcl_main_project.runs/impl_1/caliptra_tcl_main_project_bd_wrapper.bin`

### AXI Memory Map ###
 - GPIO Out
   - `0x80000000 [1] -> cptra_pwrgood`
   - `0x80000000 [0] -> cptra_rst_b`
 - GPIO In
   - `0x80000008 [31] <- ready_for_fuses`
 - ROM Backdoor
   - `0x82000000 - 0x82007FFF`
 - Caliptra
   - `0x90000000`

### Loading and Execution Steps: ###
1. Install FPGA image
    - `sudo fpgautil -b caliptra_tcl_main_project_bd_wrapper.bin -f Full -n Full`
1. Insert kernel modules for IO access
    - Branch with kernel modules: https://github.com/chipsalliance/caliptra-sw/tree/jlmahowa/fpga-kernel-modules
    - As root:
      - `cd fpga/rom_backdoor`
      - `make`
      - `insmod rom_backdoor.ko`
      - `cd fpga/io_module`
      - `make`
      - `insmod io_module.ko`
      - `chmod 666 /dev/uio4`
1. Load ROM image using backdoor
    - `dd if=caliptra-rom.bin of=/dev/caliptra-rom-backdoor`
1. Execute test targetting fpga_realtime
    - `CPTRA_UIO_NUM=4 cargo test -p caliptra-test --features=fpga_realtime smoke_test`
