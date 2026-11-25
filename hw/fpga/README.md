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

# Caliptra 2.2 FPGA Runtime & JTAG Assets

All FPGA RTL wrapper sources, Vivado build scripts (`fpga_configuration.tcl`), bitstream build workflows, and NixOS SD card image definitions have been consolidated into [`chipsalliance/caliptra-infra`](https://github.com/chipsalliance/caliptra-infra):

- **FPGA RTL & Bitstream Builds**: [`chipsalliance/caliptra-infra/hw/2.2/`](https://github.com/chipsalliance/caliptra-infra/tree/main/hw)
- **NixOS FPGA SD Card Images**: [`chipsalliance/caliptra-infra/ci-tools/fpga-image/`](https://github.com/chipsalliance/caliptra-infra/tree/main/ci-tools/fpga-image)

## Retained Runtime Files

This directory retains only the host/runtime files referenced by `caliptra-hw-model`, `xtask`, and FPGA test workflows:

- **`bitstream_manifests/`**: Pinned prebuilt bitstream manifests (`core.toml`, `subsystem.toml`) downloaded by CI and `cargo xtask`.
- **`openocd_caliptra.txt`, `openocd_ss.cfg`, `openocd_sysfsgpio_adapter.cfg`**: OpenOCD JTAG TAP configuration files embedded by `caliptra-hw-model`.
- **`io_module/`, `rom_backdoor/`, `setup_fpga.sh`**: Legacy runtime helper scripts and UIO/backdoor drivers for non-NixOS developer setups.
