# Licensed under the Apache-2.0 license

# Default settings:
set BUILD FALSE
set GUI   FALSE
set OUTPUT_DIR caliptra_build
set ITRNG TRUE
set CG_EN FALSE
set RTL_VERSION latest
set BOARD VCK190
set ITRNG TRUE
set CORE_CLK_MHZ 18
# Xilinx core requires 100 - 300MHz. Actual clock usually rounds down
set I3C_CLK_MHZ 120
# 1000 - 12500
set I3C_SCL_RATE_KHZ 1000

set SEGMENTED FALSE
set SEGMENTED_WRITE_NCR FALSE
# Simplistic processing of command line arguments to override defaults
foreach arg $argv {
  regexp {(.*)=(.*)} $arg fullmatch option value
  set $option "$value"
}
# If VERSION was not set by tclargs, set it from the commit ID.
# This assumes it is run from within caliptra-sw. If building from outside caliptra-sw call with "VERSION=[hex number]"
if {[info exists VERSION] == 0} {
  set VERSION [exec git rev-parse --short HEAD]
}

# Create path variables
set fpgaDir [file dirname [info script]]
set outputDir $fpgaDir/$OUTPUT_DIR
set caliptrapackageDir $outputDir/caliptra_package

# Clean and create output directory.
file delete -force $outputDir
file mkdir $outputDir
file mkdir $caliptrapackageDir

# Path to rtl
set rtlDir $fpgaDir/../$RTL_VERSION/rtl
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
lappend VERILOG_OPTIONS FPGA_VERSION=32'h$VERSION
# Needed to inform Adam's Bridge to use key vault params. TODO: Still need to test if this works
lappend VERILOG_OPTIONS CALIPTRA

# Start the Vivado GUI for interactive debug
if {$GUI} {
  start_gui
}

if {$BOARD eq "VCK190"} {
  set PART xcvc1902-vsva2197-2MP-e-S
  set BOARD_PART xilinx.com:vck190:part0:3.1
} elseif {$BOARD eq "VMK180"} {
  set PART xcvm1802-vsva2197-2MP-e-S
  set BOARD_PART xilinx.com:vmk180:part0:3.1
} else {
  puts "Board $BOARD not supported"
  exit
}

##### Caliptra Package #####
source create_caliptra_package.tcl
##### Caliptra Package #####

# Create a project for the SOC connections
create_project caliptra_fpga_project $outputDir -part $PART
set_property board_part $BOARD_PART [current_project]
if {$SEGMENTED} {
  set_property segmented_configuration true [current_project]
}

# Include the packaged IP
set_property  ip_repo_paths "$caliptrapackageDir" [current_project]
update_ip_catalog

# Create SOC block design
create_bd_design "caliptra_fpga_project_bd"

# Add Caliptra package
create_bd_cell -type ip -vlnv design:user:caliptra_package_top:1.0 caliptra_package_top_0

#### Add Versal PS ####
source create_versal_cips.tcl

# Create XDC file with jtag constraints
set xdc_fd [ open $outputDir/jtag_constraints.xdc w ]
puts $xdc_fd {create_clock -period 5000.000 -name {jtag_clk} -waveform {0.000 2500.000} [get_pins {caliptra_fpga_project_bd_i/ps_0/inst/pspmc_0/inst/PS9_inst/EMIOGPIO2O[0]}]}
puts $xdc_fd {set_clock_groups -asynchronous -group [get_clocks {jtag_clk}]}
close $xdc_fd

#### Add AXI Infrastructure
create_bd_cell -type ip -vlnv xilinx.com:ip:smartconnect:1.0 axi_interconnect_0
set_property -dict [list \
  CONFIG.NUM_MI {4} \
  CONFIG.NUM_SI {2} \
] [get_bd_cells axi_interconnect_0]

# Add AXI Firewall to protect the core from crashes
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_firewall:1.2 axi_firewall_0
set_property -dict [list \
  CONFIG.ARUSER_WIDTH {32} \
  CONFIG.AWUSER_WIDTH {32} \
  CONFIG.BUSER_WIDTH {32} \
  CONFIG.RUSER_WIDTH {32} \
  CONFIG.WUSER_WIDTH {32} \
  CONFIG.FIREWALL_MODE {MI_SIDE} \
  ] [get_bd_cells axi_firewall_0]

#### Add Devices ####

# Create reset block
create_bd_cell -type ip -vlnv xilinx.com:ip:proc_sys_reset:5.0 proc_sys_reset_0

# Add AXI BRAM Controller for backdoor access to IMEM
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_bram_ctrl:4.1 cptra_rom_backdoor_bram_0
set_property CONFIG.SINGLE_PORT_BRAM {1} [get_bd_cells cptra_rom_backdoor_bram_0]

#### axi_interconnect_0 ####
# AXI Managers
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/S00_AXI] [get_bd_intf_pins $ps_m_axi]
# Caliptra M_AXI
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/S01_AXI] [get_bd_intf_pins caliptra_package_top_0/M_AXI_CALIPTRA] 

# AXI Subordinates
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M00_AXI] [get_bd_intf_pins caliptra_package_top_0/S_AXI_WRAPPER]
# Connect Caliptra through a firewall
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M01_AXI] [get_bd_intf_pins axi_firewall_0/S_AXI]
connect_bd_intf_net [get_bd_intf_pins axi_firewall_0/M_AXI] [get_bd_intf_pins caliptra_package_top_0/S_AXI_CALIPTRA]

connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M02_AXI] [get_bd_intf_pins cptra_rom_backdoor_bram_0/S_AXI]
connect_bd_intf_net [get_bd_intf_pins axi_interconnect_0/M03_AXI] [get_bd_intf_pins axi_firewall_0/S_AXI_CTL]

# Connect BRAM controllers to FPGA wrapper
connect_bd_intf_net [get_bd_intf_pins caliptra_package_top_0/rom_backdoor] [get_bd_intf_pins cptra_rom_backdoor_bram_0/BRAM_PORTA]

# Create reset connections
connect_bd_net [get_bd_pins $ps_pl_resetn] [get_bd_pins proc_sys_reset_0/ext_reset_in]
connect_bd_net -net proc_sys_reset_0_peripheral_aresetn \
  [get_bd_pins proc_sys_reset_0/peripheral_aresetn] \
  [get_bd_pins axi_interconnect_0/aresetn] \
  [get_bd_pins caliptra_package_top_0/S_AXI_WRAPPER_ARESETN] \
  [get_bd_pins cptra_rom_backdoor_bram_0/s_axi_aresetn] \
  [get_bd_pins axi_firewall_0/aresetn]
# Connect auxillary reset source to package
connect_bd_net [get_bd_pins caliptra_package_top_0/axi_reset] [get_bd_pins proc_sys_reset_0/aux_reset_in]

# Create clock connections
connect_bd_net \
  [get_bd_pins $ps_pl_clk] \
  [get_bd_pins $ps_axi_aclk] \
  [get_bd_pins proc_sys_reset_0/slowest_sync_clk] \
  [get_bd_pins axi_interconnect_0/aclk] \
  [get_bd_pins caliptra_package_top_0/core_clk] \
  [get_bd_pins cptra_rom_backdoor_bram_0/s_axi_aclk] \
  [get_bd_pins caliptra_ss_package_0/core_clk] \
  [get_bd_pins axi_firewall_0/aclk]


# Create address segments for all AXI managers
set managers {ps_0/M_AXI_FPD caliptra_package_top_0/M_AXI_CALIPTRA}
foreach manager $managers {
  assign_bd_address -offset 0xB0000000 -range 0x00018000 -target_address_space [get_bd_addr_spaces $manager] [get_bd_addr_segs cptra_rom_backdoor_bram_0/S_AXI/Mem0] -force
  assign_bd_address -offset 0xA4010000 -range 0x00002000 -target_address_space [get_bd_addr_spaces $manager] [get_bd_addr_segs caliptra_package_top_0/S_AXI_WRAPPER/reg0] -force
  # AXI Firewall Control
  assign_bd_address -offset 0xA4090000 -range 0x00001000 -target_address_space [get_bd_addr_spaces $manager] [get_bd_addr_segs axi_firewall_0/S_AXI_CTL/Control] -force
  assign_bd_address -offset 0xA4100000 -range 0x00100000 -target_address_space [get_bd_addr_spaces $manager] [get_bd_addr_segs caliptra_package_top_0/S_AXI_CALIPTRA/reg0] -force
}

# Connect JTAG signals to PS GPIO pins
connect_bd_net [get_bd_pins caliptra_package_top_0/jtag_out] [get_bd_pins $ps_gpio_i]
connect_bd_net [get_bd_pins caliptra_package_top_0/jtag_in] [get_bd_pins $ps_gpio_o]

# Add constraints for JTAG signals
add_files -fileset constrs_1 $outputDir/jtag_constraints.xdc

save_bd_design
puts "Fileset when setting defines the second time: [current_fileset]"
set_property verilog_define $VERILOG_OPTIONS [current_fileset]
puts "\n\nVERILOG DEFINES: [get_property verilog_define [current_fileset]]"

# Create the HDL wrapper for the block design and add it. This will be set as top.
make_wrapper -files [get_files $outputDir/caliptra_fpga_project.srcs/sources_1/bd/caliptra_fpga_project_bd/caliptra_fpga_project_bd.bd] -top
add_files -norecurse $outputDir/caliptra_fpga_project.gen/sources_1/bd/caliptra_fpga_project_bd/hdl/caliptra_fpga_project_bd_wrapper.v
set_property top caliptra_fpga_project_bd_wrapper [current_fileset]

update_compile_order -fileset sources_1

# Assign the gated clock conversion setting in the caliptra_package_top out of context run.
create_ip_run [get_files caliptra_fpga_project_bd.bd]
set_property STEPS.SYNTH_DESIGN.ARGS.GATED_CLOCK_CONVERSION $GATED_CLOCK_CONVERSION [get_runs caliptra_fpga_project_bd_caliptra_package_top_0_0_synth_1]

# Add DDR pin placement constraints
file copy $fpgaDir/src/ddr4_constraints.xdc $outputDir/ddr4_constraints.xdc
add_files -fileset constrs_1 $outputDir/ddr4_constraints.xdc

# Set initial boot property to make the NOC connections part of the boot PDI.
if {$SEGMENTED} {
  set_property initial_boot true [get_noc_logical_paths]
}

# Load a previous NCR
if {$SEGMENTED} {
  read_noc_solution -file $fpgaDir/saved_noc_solution.ncr
}

# Start build
if {$BUILD} {
  set time_start_synth [clock clicks -millisec]
  launch_runs synth_1 -jobs 32
  wait_on_runs synth_1
  set time_finish_synth [clock clicks -millisec]

  set time_start_impl [clock clicks -millisec]
  launch_runs impl_1 -to_step write_device_image -jobs 32
  wait_on_runs impl_1
  set time_finish_impl [clock clicks -millisec]

  set time_start_hw_platform [clock clicks -millisec]
  open_run impl_1
  report_utilization -file $outputDir/utilization.txt
  if {$SEGMENTED} {
    if {$SEGMENTED_WRITE_NCR} {
      # Lock the NoC path segments and save the solution for later builds.
      set_property lock true [get_noc_net_routes -of [get_noc_logical_paths -filter {initial_boot == 1}]]
      write_noc_solution -file $fpgaDir/saved_noc_solution.ncr
      file copy -force $outputDir/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper_routed.dcp $fpgaDir/segmented_golden_routed.dcp
      puts stderr "Replace file in GCS bucket: [exec realpath $fpgaDir/segmented_golden_routed.dcp]"
    } else {
      # Verify that the NoC Solutions are identical and the PLD images are compatible.
      exec curl -s -O "https://storage.googleapis.com/caliptra-github-ci-bitstreams/scratch/fpga_2px_golden_routed.dcp"
      pr_verify -initial $fpgaDir/fpga_2px_golden_routed.dcp -additional $outputDir/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper_routed.dcp
    }
    # Copy the PDI containing runtime info to a more convenient location.
    file copy $outputDir/caliptra_fpga_project.runs/impl_1/caliptra_fpga_project_bd_wrapper_pld.pdi $outputDir/runtime_$VERSION.pdi
  }

  write_hw_platform -fixed -include_bit -force -file $outputDir/caliptra_fpga.xsa
  set time_finish_hw_platform [clock clicks -millisec]

  puts stderr "FPGA Synthesis      took [expr {($time_finish_synth-$time_start_synth)/60000.}] minutes"
  puts stderr "FPGA Implementation took [expr {($time_finish_impl-$time_start_impl)/60000.}] minutes"
  puts stderr "FPGA Write HW Plat  took [expr {($time_finish_hw_platform-$time_start_hw_platform)/60000.}] minutes"
  puts stderr "FPGA overall build  took [expr {($time_finish_hw_platform-$time_start_synth)/60000.}] minutes"

  set build_time [ open $outputDir/build_time.txt w ]
  puts $build_time "Built from $VERSION"
  puts $build_time "FPGA Synthesis      took [expr {($time_finish_synth-$time_start_synth)/60000.}] minutes"
  puts $build_time "FPGA Implementation took [expr {($time_finish_impl-$time_start_impl)/60000.}] minutes"
  puts $build_time "FPGA Write HW Plat  took [expr {($time_finish_hw_platform-$time_start_hw_platform)/60000.}] minutes"
  puts $build_time "FPGA overall build  took [expr {($time_finish_hw_platform-$time_start_synth)/60000.}] minutes"
  close $build_time
}
