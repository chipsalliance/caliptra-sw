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

### ZCU104 Processing System One Time Setup: ###
1. Install ZCU104 SD card image
   - https://ubuntu.com/download/amd-xilinx
1. Configure SW6 to boot from SD1.
   - Mode SW6[4:1]: OFF, OFF, OFF, ON
1. Install rustup using Unix directions: https://rustup.rs/#
1. apt install libssl-dev

#### Serial port configuration ####
Serial port settings for connection over USB.
 - Speed: 115200
 - Data bits: 8
 - Stop bits: 1
 - Parity: None
 - Flow control: None

### FPGA Build Steps: ###
1. Launch Vivado with tcl script defining FPGA build
    - `vivado -mode batch -source fpga_configuration.tcl`
1. Run Synthesis
    - Use GUI or: `launch_runs synth_1`
1. Set Up Debug signals on Synthesized Design
1. Run Implementation and generate bitstream
    - Use GUI or: `launch_runs impl_1`
1. FPGA image location:
    - `caliptra_build/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper.bin`

### AXI Memory Map ###
 - SOC adapter
   - 0x80000000 - GPIO Out -> Caliptra
     - `[0] -> cptra_rst_b`
     - `[1] -> cptra_pwrgood`
     - `[5:4] -> device_lifecycle`
     - `[6] -> debug_locked`
     - `[31:24] -> generic_input_wires[7:0] for serial tag`
   - 0x80000008 - GPIO In <- Caliptra
     - `[26] <- cptra_error_fatal`
     - `[27] <- cptra_error_non_fatal`
     - `[28] <- ready_for_fw_push`
     - `[29] <- ready_for_runtime`
     - `[30] <- ready_for_fuses`
   - 0x8000000C - PAUSER
     - `[31:0] -> PAUSER to Caliptra APB`
 - ROM Backdoor
   - `0x82000000 - 0x82007FFF`
 - Caliptra
   - `0x90000000`

### Loading and Execution Steps: ###
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
1. Execute test targeting fpga_realtime
    - `CPTRA_UIO_NUM=4 cargo test -p caliptra-test --features=fpga_realtime smoke_test`
