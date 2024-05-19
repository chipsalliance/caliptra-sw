# Create path variables
set fpgaDir [file dirname [info script]]
set outputDir $fpgaDir/caliptra_build
set packageDir $outputDir/caliptra_package
set adapterDir $outputDir/soc_adapter_package
# Clean and create output directory.
file delete -force $outputDir
file mkdir $outputDir
file mkdir $packageDir
file mkdir $adapterDir

# Simplistic processing of command line arguments to enable different features
# Defaults:
set BUILD FALSE
set GUI   FALSE
set JTAG  TRUE
set ITRNG TRUE
set CG_EN FALSE
set RTL_VERSION latest
set BOARD ZCU104
foreach arg $argv {
    regexp {(.*)=(.*)} $arg fullmatch option value
    set $option "$value"
}
# If VERSION was not set by tclargs, set it from the commit ID.
# This assumes it is run from within caliptra-sw. If building from outside caliptra-sw call with "VERSION=[hex number]"
if {[info exists VERSION] == 0} {
  set VERSION [exec git rev-parse --short HEAD]
}

# Path to rtl
set rtlDir $fpgaDir/../$RTL_VERSION/rtl
puts "JTAG: $JTAG"
puts "ITRNG: $ITRNG"
puts "CG_EN: $CG_EN"
puts "RTL_VERSION: $RTL_VERSION"
puts "Using RTL directory $rtlDir"

# Set Verilog defines for:
#     Caliptra clock gating module
#     VEER clock gating module
#     VEER core FPGA optimizations (disables clock gating)
if {$CG_EN} {
  set VERILOG_OPTIONS {TECH_SPECIFIC_ICG USER_ICG=fpga_real_icg TECH_SPECIFIC_EC_RV_ICG USER_EC_RV_ICG=fpga_rv_clkhdr}
  set GATED_CLOCK_CONVERSION auto
} else {
  set VERILOG_OPTIONS {TECH_SPECIFIC_ICG USER_ICG=fpga_fake_icg RV_FPGA_OPTIMIZE TEC_RV_ICG=clockhdr}
  set GATED_CLOCK_CONVERSION off
}
if {$ITRNG} {
  # Add option to use Caliptra's internal TRNG instead of ETRNG
  lappend VERILOG_OPTIONS CALIPTRA_INTERNAL_TRNG
}

# Start the Vivado GUI for interactive debug
if {$GUI} {
  start_gui
}

if {$BOARD eq "ZCU104"} {
  set PART xczu7ev-ffvc1156-2-e
} elseif {$BOARD eq "VCK190"} {
  set PART xcvc1902-vsva2197-2MP-e-S
} else {
  puts "Board $BOARD not supported"
  exit
}

# Create a project to package Caliptra.
# Packaging Caliptra allows Vivado to recognize the APB bus as an endpoint for the memory map.
create_project caliptra_package_project $outputDir -part $PART

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
add_files [ glob $fpgaDir/src/*.sv]
add_files [ glob $fpgaDir/src/*.v]

# Mark all Verilog sources as SystemVerilog because some of them have SystemVerilog syntax.
set_property file_type SystemVerilog [get_files *.v]

# Exception: caliptra_package_top.v needs to be Verilog to be included in a Block Diagram.
set_property file_type Verilog [get_files  $fpgaDir/src/caliptra_package_top.v]

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
ipx::associate_bus_interfaces -busif S_AXI -clock core_clk [ipx::current_core]
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
create_project caliptra_fpga_project $outputDir -part $PART

# Include the packaged IP
set_property  ip_repo_paths  "$packageDir $adapterDir" [current_project]
update_ip_catalog

# Create SOC block design
create_bd_design "caliptra_fpga_project_bd"

# Add Caliptra package
create_bd_cell -type ip -vlnv design:user:caliptra_package_top:1.0 caliptra_package_top_0

# Add Zynq/Versal PS
if {$BOARD eq "ZCU104"} {
  create_bd_cell -type ip -vlnv xilinx.com:ip:zynq_ultra_ps_e ps_0
  set_property -dict [list \
    CONFIG.PSU__CRL_APB__PL0_REF_CTRL__FREQMHZ {20} \
    CONFIG.PSU__USE__IRQ0 {1} \
    CONFIG.PSU__GPIO_EMIO__PERIPHERAL__ENABLE {1} \
    CONFIG.PSU__GPIO_EMIO__PERIPHERAL__IO {5} \
  ] [get_bd_cells ps_0]

  # Create variables to adapt between PS
  set ps_m_axi ps_0/M_AXI_HPM0_LPD
  set ps_pl_clk ps_0/pl_clk0
  set ps_axi_aclk ps_0/maxihpm0_lpd_aclk
  set ps_pl_resetn ps_0/pl_resetn0
  set ps_gpio_i ps_0/emio_gpio_i
  set ps_gpio_o ps_0/emio_gpio_o

  # Create XDC file with constraints
  set xdc_fd [ open $outputDir/jtag_constraints.xdc w ]
  puts $xdc_fd {create_clock -period 5000.000 -name {jtag_clk} -waveform {0.000 2500.000} [get_pins {caliptra_fpga_project_bd_i/ps_0/inst/PS8_i/EMIOGPIOO[0]}]}
  puts $xdc_fd {set_clock_groups -asynchronous -group [get_clocks {jtag_clk}]}
  close $xdc_fd

} else {
  create_bd_cell -type ip -vlnv xilinx.com:ip:versal_cips:3.3 ps_0
  set_property -dict [list \
    CONFIG.CPM_CONFIG { \
      CPM_PCIE0_MODES {None} \
    } \
    CONFIG.PS_PL_CONNECTIVITY_MODE {Custom} \
    CONFIG.PS_PMC_CONFIG { \
      DESIGN_MODE {1} \
      PMC_CRP_PL0_REF_CTRL_FREQMHZ {20} \
      PS_BOARD_INTERFACE {Custom} \
      PS_CRL_LPD_LSBUS_CTRL_FREQMHZ {20} \
      PS_GPIO_EMIO_PERIPHERAL_ENABLE {1} \
      PS_GPIO_EMIO_WIDTH {5} \
      PS_M_AXI_LPD_DATA_WIDTH {32} \
      PS_NUM_FABRIC_RESETS {1} \
      PS_PL_CONNECTIVITY_MODE {Custom} \
      PS_USE_M_AXI_LPD {1} \
      PS_USE_PMCPL_CLK0 {1} \
      SMON_ALARMS {Set_Alarms_On} \
      SMON_ENABLE_TEMP_AVERAGING {0} \
      SMON_TEMP_AVERAGING_SAMPLES {0} \
    } \
  ] [get_bd_cells ps_0]

  # Create variables to adapt between PS
  set ps_m_axi ps_0/M_AXI_LPD
  set ps_pl_clk ps_0/pl0_ref_clk
  set ps_axi_aclk ps_0/m_axi_lpd_aclk
  set ps_pl_resetn ps_0/pl0_resetn
  set ps_gpio_i ps_0/LPD_GPIO_i
  set ps_gpio_o ps_0/LPD_GPIO_o

  # Create XDC file with constraints
  set xdc_fd [ open $outputDir/jtag_constraints.xdc w ]
  puts $xdc_fd {create_clock -period 5000.000 -name {jtag_clk} -waveform {0.000 2500.000} [get_pins {caliptra_fpga_project_bd_i/ps_0/inst/pspmc_0/inst/PS9_inst/EMIOGPIO2O[0]}]}
  puts $xdc_fd {set_clock_groups -asynchronous -group [get_clocks {jtag_clk}]}
  close $xdc_fd
}

# Add AXI Interconnect
create_bd_cell -type ip -vlnv xilinx.com:ip:smartconnect:1.0 axi_interconnect_0
set_property -dict [list \
  CONFIG.NUM_MI {3} \
  CONFIG.NUM_SI {1} \
] [get_bd_cells axi_interconnect_0]

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
set_property location {1 177 345} [get_bd_cells ps_0]
set_property location {2 696 373} [get_bd_cells axi_interconnect_0]
set_property location {2 707 654} [get_bd_cells proc_sys_reset_0]
set_property location {3 1041 439} [get_bd_cells axi_apb_bridge_0]
set_property location {3 1151 617} [get_bd_cells axi_bram_ctrl_0]
set_property location {4 1335 456} [get_bd_cells caliptra_package_top_0]

# Create AXI bus connections
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/S00_AXI] [get_bd_intf_pins $ps_m_axi]
# AXI for FPGA wrapper registers
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M00_AXI] [get_bd_intf_pins caliptra_package_top_0/S_AXI]
# AXI to APB for Caliptra
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M01_AXI] [get_bd_intf_pins axi_apb_bridge_0/AXI4_LITE]
connect_bd_intf_net [get_bd_intf_pins axi_apb_bridge_0/APB_M] [get_bd_intf_pins caliptra_package_top_0/s_apb]
# AXI connection to program ROM
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M02_AXI] [get_bd_intf_pins axi_bram_ctrl_0/S_AXI]
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/axi_bram] [get_bd_intf_pins axi_bram_ctrl_0/BRAM_PORTA]

# Create reset connections
connect_bd_net [get_bd_pins $ps_pl_resetn] [get_bd_pins proc_sys_reset_0/ext_reset_in]
connect_bd_net -net proc_sys_reset_0_peripheral_aresetn \
  [get_bd_pins proc_sys_reset_0/peripheral_aresetn] \
  [get_bd_pins axi_apb_bridge_0/s_axi_aresetn] \
  [get_bd_pins axi_interconnect_0/aresetn] \
  [get_bd_pins caliptra_package_top_0/S_AXI_ARESETN] \
  [get_bd_pins axi_bram_ctrl_0/s_axi_aresetn]
# Create clock connections
connect_bd_net -net ps_0_pl0_ref_clk \
  [get_bd_pins $ps_pl_clk] \
  [get_bd_pins $ps_axi_aclk] \
  [get_bd_pins proc_sys_reset_0/slowest_sync_clk] \
  [get_bd_pins axi_apb_bridge_0/s_axi_aclk] \
  [get_bd_pins axi_interconnect_0/aclk] \
  [get_bd_pins caliptra_package_top_0/core_clk] \
  [get_bd_pins axi_bram_ctrl_0/s_axi_aclk]

# Create address segments
assign_bd_address -offset 0x80000000 -range 0x00002000 -target_address_space [get_bd_addr_spaces ps_0/Data] [get_bd_addr_segs caliptra_package_top_0/S_AXI/reg0] -force
assign_bd_address -offset 0x82000000 -range 0x00010000 -target_address_space [get_bd_addr_spaces ps_0/Data] [get_bd_addr_segs axi_bram_ctrl_0/S_AXI/Mem0] -force
assign_bd_address -offset 0x90000000 -range 0x00100000 -target_address_space [get_bd_addr_spaces ps_0/Data] [get_bd_addr_segs caliptra_package_top_0/s_apb/Reg] -force

# Connect JTAG signals to PS GPIO pins
connect_bd_net [get_bd_pins caliptra_package_top_0/jtag_out] [get_bd_pins $ps_gpio_i]
connect_bd_net [get_bd_pins caliptra_package_top_0/jtag_in] [get_bd_pins $ps_gpio_o]

# Add constraints for JTAG signals
add_files -fileset constrs_1 $outputDir/jtag_constraints.xdc

save_bd_design
set_property verilog_define $VERILOG_OPTIONS [current_fileset]

# Create the HDL wrapper for the block design and add it. This will be set as top.
make_wrapper -files [get_files $outputDir/caliptra_fpga_project.srcs/sources_1/bd/caliptra_fpga_project_bd/caliptra_fpga_project_bd.bd] -top
add_files -norecurse $outputDir/caliptra_fpga_project.gen/sources_1/bd/caliptra_fpga_project_bd/hdl/caliptra_fpga_project_bd_wrapper.v

update_compile_order -fileset sources_1

# Assign the gated clock conversion setting in the caliptra_package_top out of context run.
create_ip_run [get_files *.bd]
set_property STEPS.SYNTH_DESIGN.ARGS.GATED_CLOCK_CONVERSION $GATED_CLOCK_CONVERSION [get_runs caliptra_fpga_project_bd_caliptra_package_top_0_0_synth_1]

# The FPGA loading methods currently in use require the bin file to be generated.
if {$BOARD eq "ZCU104"} {
  set_property STEPS.WRITE_BITSTREAM.ARGS.BIN_FILE true [get_runs impl_1]
}

# Start build
if {$BUILD} {
  launch_runs synth_1 -jobs 10
  wait_on_runs synth_1
  launch_runs impl_1 -jobs 10
  wait_on_runs impl_1
  open_run impl_1
  report_utilization -file $outputDir/utilization.txt
  # Embed git hash in USR_ACCESS register for bitstream identification.
  set_property BITSTREAM.CONFIG.USR_ACCESS 0x$VERSION [current_design]
  write_bitstream -bin_file $outputDir/caliptra_fpga
}
