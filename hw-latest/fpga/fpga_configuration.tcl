# Clean and create output directory.
set outputDir ./caliptra_build
set packageDir $outputDir/caliptra_package
set adapterDir $outputDir/soc_adapter_package
file delete -force $outputDir
file mkdir $outputDir
file mkdir $packageDir
file mkdir $adapterDir

# Path to rtl
set rtlDir ../caliptra-rtl

# Simplistic processing of command line arguments to enable different features
# Defaults:
set BUILD FALSE
set GUI   FALSE
set JTAG  TRUE
set ITRNG FALSE
foreach arg $argv {
    regexp {(.*)=(.*)} $arg fullmatch option value
    set $option "$value"
}

# Set Verilog defines to:
#     Make Caliptra use an icg that doesn't clock gate
#     Make the VEER core be optimized for FPGA (no clock gating)
#     Define VEER TEC_RV_ICG to allow beh_lib to synthesise without error
set VERILOG_OPTIONS {TECH_SPECIFIC_ICG USER_ICG=fpga_fake_icg RV_FPGA_OPTIMIZE TEC_RV_ICG=clockhdr}
if {$ITRNG} {
  # Add option to use Caliptra's internal TRNG instead of ETRNG
  lappend VERILOG_OPTIONS CALIPTRA_INTERNAL_TRNG
}

# Start the Vivado GUI for interactive debug
if {$GUI} {
  start_gui
}

# Create a project to package a module to connect SOC signals to
create_project soc_adapter_package_project $outputDir -part xczu7ev-ffvc1156-2-e
# Add source
add_files [ glob ./src/soc_adapter.v ]

# Package IP
ipx::package_project -root_dir $adapterDir -vendor design -library user -taxonomy /UserIP -import_files -set_current false
ipx::unload_core $adapterDir/component.xml
ipx::edit_ip_in_project -upgrade true -name tmp_edit_project -directory $adapterDir $adapterDir/component.xml
ipx::infer_bus_interfaces xilinx.com:interface:axi:1.0 [ipx::current_core]
set_property core_revision 1 [ipx::current_core]
ipx::update_source_project_archive -component [ipx::current_core]
ipx::create_xgui_files [ipx::current_core]
ipx::update_checksums [ipx::current_core]
ipx::check_integrity [ipx::current_core]
ipx::save_core [ipx::current_core]
# Close temp project
close_project
# Close soc_adapter_package_project
close_project


# Create a project to package Caliptra.
# Packaging Caliptra allows Vivado to recognize the APB bus as an endpoint for the memory map.
create_project caliptra_package_project $outputDir -part xczu7ev-ffvc1156-2-e

# Generate IRAM
create_ip -name blk_mem_gen -vendor xilinx.com -library ip -version 8.4 -module_name fpga_imem -dir $outputDir
set_property -dict [list \
  CONFIG.Memory_Type {True_Dual_Port_RAM} \
  CONFIG.Write_Depth_A {4096} \
  CONFIG.Write_Width_A {64} \
  CONFIG.Write_Width_B {32} \
  CONFIG.Use_RSTB_Pin {true} \
  CONFIG.Byte_Size {8} \
  CONFIG.Use_Byte_Write_Enable {true} \
  CONFIG.Register_PortA_Output_of_Memory_Primitives {false} \
  CONFIG.Register_PortB_Output_of_Memory_Primitives {false} \
] [get_ips fpga_imem]

# Generate Mailbox RAM. 128K
create_ip -name blk_mem_gen -vendor xilinx.com -library ip -version 8.4 -module_name fpga_mbox_ram -dir $outputDir
set_property -dict [list \
  CONFIG.Memory_Type {Single_Port_RAM} \
  CONFIG.Write_Depth_A {32768} \
  CONFIG.Write_Width_A {39} \
  CONFIG.Register_PortA_Output_of_Memory_Primitives {false} \
] [get_ips fpga_mbox_ram]

# Generate ECC TDP File
create_ip -name blk_mem_gen -vendor xilinx.com -library ip -version 8.4 -module_name fpga_ecc_ram_tdp_file -dir $outputDir
set_property -dict [list \
  CONFIG.Memory_Type {True_Dual_Port_RAM} \
  CONFIG.Write_Depth_A {64} \
  CONFIG.Write_Width_A {384} \
  CONFIG.Write_Width_B {384} \
  CONFIG.Use_RSTA_Pin {true} \
  CONFIG.Register_PortA_Output_of_Memory_Primitives {false} \
  CONFIG.Register_PortB_Output_of_Memory_Primitives {false} \
] [get_ips fpga_ecc_ram_tdp_file]

set_property verilog_define $VERILOG_OPTIONS [current_fileset]

# Add VEER Headers
add_files $rtlDir/src/riscv_core/veer_el2/rtl/el2_param.vh
add_files $rtlDir/src/riscv_core/veer_el2/rtl/pic_map_auto.h
add_files $rtlDir/src/riscv_core/veer_el2/rtl/el2_pdef.vh

# Add VEER sources
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/*.sv ]
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/*/*.sv ]
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/*/*.v ]

# Add Caliptra Headers
add_files [ glob $rtlDir/src/*/rtl/*.svh ]
# Add Caliptra Sources
add_files [ glob $rtlDir/src/*/rtl/*.sv ]
add_files [ glob $rtlDir/src/*/rtl/*.v ]

# Remove spi_host files that aren't used yet and are flagged as having syntax errors
# TODO: Re-include these files when spi_host is used.
remove_files [ glob $rtlDir/src/spi_host/rtl/*.sv ]

# Remove Caliptra files that need to be replaced by FPGA specific versions
# Replace RAM with FPGA block ram
remove_files [ glob $rtlDir/src/ecc/rtl/ecc_ram_tdp_file.sv ]
# Key Vault is very large. Replacing KV with a version with the minimum number of entries.
remove_files [ glob $rtlDir/src/keyvault/rtl/kv_reg.sv ]

# Add FPGA specific sources
add_files [ glob ./src/*.sv]
add_files [ glob ./src/*.v]

# Mark all Verilog sources as SystemVerilog because some of them have SystemVerilog syntax.
set_property file_type SystemVerilog [get_files *.v]

# Exception: caliptra_package_top.v needs to be Verilog to be included in a Block Diagram.
set_property file_type Verilog [get_files  ./src/caliptra_package_top.v]

# Add include paths
set_property include_dirs $rtlDir/src/integration/rtl [current_fileset]


# Set caliptra_package_top as top in case next steps fail so that the top is something useful.
set_property top caliptra_package_top [current_fileset]

# Create block diagram that includes an instance of caliptra_package_top
create_bd_design "caliptra_package_bd"
create_bd_cell -type module -reference caliptra_package_top caliptra_package_top_0
save_bd_design
close_bd_design [get_bd_designs caliptra_package_bd]

# Package IP
ipx::package_project -root_dir $packageDir -vendor design -library user -taxonomy /UserIP -import_files -set_current false
ipx::unload_core $packageDir/component.xml
ipx::edit_ip_in_project -upgrade true -name tmp_edit_project -directory $packageDir $packageDir/component.xml
ipx::infer_bus_interfaces xilinx.com:interface:apb_rtl:1.0 [ipx::current_core]
ipx::infer_bus_interfaces xilinx.com:interface:bram_rtl:1.0 [ipx::current_core]
set_property core_revision 1 [ipx::current_core]
ipx::update_source_project_archive -component [ipx::current_core]
ipx::create_xgui_files [ipx::current_core]
ipx::update_checksums [ipx::current_core]
ipx::check_integrity [ipx::current_core]
ipx::save_core [ipx::current_core]

# Close temp project
close_project
# Close caliptra_package_project
close_project

# Packaging complete

# Create a project for the SOC connections
create_project caliptra_fpga_project $outputDir -part xczu7ev-ffvc1156-2-e

# Include the packaged IP
set_property  ip_repo_paths  "$packageDir $adapterDir" [current_project]
update_ip_catalog

# Create SOC block design
create_bd_design "caliptra_fpga_project_bd"

# Add Caliptra package
create_bd_cell -type ip -vlnv design:user:caliptra_package_top:1.0 caliptra_package_top_0

# Add Zynq PS
create_bd_cell -type ip -vlnv xilinx.com:ip:zynq_ultra_ps_e:3.4 zynq_ultra_ps_e_0
set_property CONFIG.PSU__CRL_APB__PL0_REF_CTRL__FREQMHZ {20} [get_bd_cells zynq_ultra_ps_e_0]

# Add AXI Interconnect
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_interconnect:2.1 axi_interconnect_0
set_property CONFIG.NUM_MI {3} [get_bd_cells axi_interconnect_0]

# Add caliptra_soc
create_bd_cell -type ip -vlnv design:user:soc_adapter:1.0 caliptra_soc_0

# Add AXI APB Bridge for Caliptra
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_apb_bridge:3.0 axi_apb_bridge_0
set_property -dict [list \
  CONFIG.C_APB_NUM_SLAVES {1} \
  CONFIG.C_M_APB_PROTOCOL {apb4} \
] [get_bd_cells axi_apb_bridge_0]

# Add AXI BRAM Controller for backdoor access to IMEM
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 axi_bram_ctrl_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells axi_bram_ctrl_0]

# Create reset block
create_bd_cell -type ip -vlnv xilinx.com:ip:proc_sys_reset:5.0 proc_sys_reset_0

# Move blocks around on the block diagram. This step is optional.
set_property location {1 177 345} [get_bd_cells zynq_ultra_ps_e_0]
set_property location {2 696 373} [get_bd_cells axi_interconnect_0]
set_property location {2 707 654} [get_bd_cells proc_sys_reset_0]
set_property location {3 1021 286} [get_bd_cells caliptra_soc_0]
set_property location {3 1041 439} [get_bd_cells axi_apb_bridge_0]
set_property location {3 1151 617} [get_bd_cells axi_bram_ctrl_0]
set_property location {4 1335 456} [get_bd_cells caliptra_package_top_0]


# Create interface connections
connect_bd_intf_net -intf_net axi_apb_bridge_0_APB_M [get_bd_intf_pins axi_apb_bridge_0/APB_M] [get_bd_intf_pins caliptra_package_top_0/s_apb]
connect_bd_intf_net -boundary_type upper [get_bd_intf_pins axi_interconnect_0/M00_AXI] [get_bd_intf_pins caliptra_soc_0/interface_aximm]
connect_bd_intf_net -intf_net axi_interconnect_0_M01_AXI [get_bd_intf_pins axi_apb_bridge_0/AXI4_LITE] [get_bd_intf_pins axi_interconnect_0/M01_AXI]
connect_bd_intf_net -intf_net zynq_ultra_ps_e_0_M_AXI_HPM0_LPD [get_bd_intf_pins axi_interconnect_0/S00_AXI] [get_bd_intf_pins zynq_ultra_ps_e_0/M_AXI_HPM0_LPD]
connect_bd_intf_net [get_bd_intf_pins axi_bram_ctrl_0/S_AXI] -boundary_type upper [get_bd_intf_pins axi_interconnect_0/M02_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/axi_bram] [get_bd_intf_pins axi_bram_ctrl_0/BRAM_PORTA]

# Create port connections
connect_bd_net -net proc_sys_reset_0_peripheral_aresetn [get_bd_pins axi_apb_bridge_0/s_axi_aresetn] [get_bd_pins caliptra_soc_0/rstn] [get_bd_pins axi_interconnect_0/ARESETN] [get_bd_pins axi_interconnect_0/M00_ARESETN] [get_bd_pins axi_interconnect_0/M01_ARESETN] [get_bd_pins axi_interconnect_0/S00_ARESETN] [get_bd_pins proc_sys_reset_0/peripheral_aresetn]
connect_bd_net -net zynq_ultra_ps_e_0_pl_clk0 [get_bd_pins axi_apb_bridge_0/s_axi_aclk] [get_bd_pins caliptra_soc_0/aclk] [get_bd_pins axi_interconnect_0/ACLK] [get_bd_pins axi_interconnect_0/M00_ACLK] [get_bd_pins axi_interconnect_0/M01_ACLK] [get_bd_pins axi_interconnect_0/S00_ACLK] [get_bd_pins caliptra_package_top_0/core_clk] [get_bd_pins proc_sys_reset_0/slowest_sync_clk] [get_bd_pins zynq_ultra_ps_e_0/maxihpm0_lpd_aclk] [get_bd_pins zynq_ultra_ps_e_0/pl_clk0]
connect_bd_net [get_bd_pins caliptra_package_top_0/gpio_in] [get_bd_pins caliptra_soc_0/gpio_out]
connect_bd_net [get_bd_pins caliptra_package_top_0/gpio_out] [get_bd_pins caliptra_soc_0/gpio_in]
connect_bd_net [get_bd_pins caliptra_package_top_0/pauser] [get_bd_pins caliptra_soc_0/pauser]
connect_bd_net [get_bd_pins caliptra_package_top_0/cptra_obf_key] [get_bd_pins caliptra_soc_0/cptra_obf_key]

connect_bd_net -net zynq_ultra_ps_e_0_pl_resetn0 [get_bd_pins proc_sys_reset_0/ext_reset_in] [get_bd_pins zynq_ultra_ps_e_0/pl_resetn0]
connect_bd_net [get_bd_pins axi_bram_ctrl_0/s_axi_aclk] [get_bd_pins zynq_ultra_ps_e_0/pl_clk0]
connect_bd_net [get_bd_pins axi_bram_ctrl_0/s_axi_aresetn] [get_bd_pins proc_sys_reset_0/peripheral_aresetn]
connect_bd_net [get_bd_pins axi_interconnect_0/M02_ACLK] [get_bd_pins zynq_ultra_ps_e_0/pl_clk0]
connect_bd_net [get_bd_pins axi_interconnect_0/M02_ARESETN] [get_bd_pins proc_sys_reset_0/peripheral_aresetn]


# Create address segments
assign_bd_address -offset 0x80000000 -range 0x00010000 -target_address_space [get_bd_addr_spaces zynq_ultra_ps_e_0/Data] [get_bd_addr_segs caliptra_soc_0/interface_aximm/reg0] -force
assign_bd_address -offset 0x82000000 -range 0x00008000 -target_address_space [get_bd_addr_spaces zynq_ultra_ps_e_0/Data] [get_bd_addr_segs axi_bram_ctrl_0/S_AXI/Mem0] -force
assign_bd_address -offset 0x90000000 -range 0x00100000 -target_address_space [get_bd_addr_spaces zynq_ultra_ps_e_0/Data] [get_bd_addr_segs caliptra_package_top_0/s_apb/Reg] -force

if {$JTAG} {
  # Make the JTAG pins be external
  make_bd_pins_external  [get_bd_pins caliptra_package_top_0/jtag_tck] [get_bd_pins caliptra_package_top_0/jtag_tms] [get_bd_pins caliptra_package_top_0/jtag_tdo] [get_bd_pins caliptra_package_top_0/jtag_tdi] [get_bd_pins caliptra_package_top_0/jtag_trst_n]

  # Add constraints for JTAG signals
  add_files -fileset constrs_1 ./src/jtag_constraints.xdc
} else {
  # Tie off JTAG inputs
  create_bd_cell -type ip -vlnv xilinx.com:ip:xlconstant:1.1 xlconstant_0
  connect_bd_net [get_bd_pins xlconstant_0/dout] [get_bd_pins caliptra_package_top_0/jtag_tck]
  connect_bd_net [get_bd_pins xlconstant_0/dout] [get_bd_pins caliptra_package_top_0/jtag_tms]
  connect_bd_net [get_bd_pins xlconstant_0/dout] [get_bd_pins caliptra_package_top_0/jtag_tdi]
  connect_bd_net [get_bd_pins xlconstant_0/dout] [get_bd_pins caliptra_package_top_0/jtag_trst_n]
}

save_bd_design
set_property verilog_define $VERILOG_OPTIONS [current_fileset]

# Create the HDL wrapper for the block design and add it. This will be set as top.
make_wrapper -files [get_files $outputDir/caliptra_fpga_project.srcs/sources_1/bd/caliptra_fpga_project_bd/caliptra_fpga_project_bd.bd] -top
add_files -norecurse $outputDir/caliptra_fpga_project.gen/sources_1/bd/caliptra_fpga_project_bd/hdl/caliptra_fpga_project_bd_wrapper.v

update_compile_order -fileset sources_1

# The FPGA loading methods currently in use require the bin file to be generated.
set_property STEPS.WRITE_BITSTREAM.ARGS.BIN_FILE true [get_runs impl_1]

# Add FPGA constraints
add_files -fileset constrs_1 ./src/constraints.xdc

# Start build
if {$BUILD} {
  launch_runs synth_1 -jobs 10
  wait_on_runs synth_1
  launch_runs impl_1 -jobs 10
  wait_on_runs impl_1
  open_run impl_1
  write_bitstream -bin_file $outputDir/caliptra_fpga
}
