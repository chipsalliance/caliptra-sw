# Licensed under the Apache-2.0 license

# Caliptra wrapper registers
python3 -m peakrdl regblock rdl_properties.rdl caliptra_fpga_realtime_regs.rdl -o ./ --cpuif axi4-lite
python3 -m peakrdl markdown rdl_properties.rdl caliptra_fpga_realtime_regs.rdl -o ../fpga_wrapper_regs.md

