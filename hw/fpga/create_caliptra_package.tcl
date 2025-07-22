
# Create a project to package Caliptra.
# Packaging Caliptra allows Vivado to recognize the APB bus as an endpoint for the memory map.
create_project caliptra_package_project $outputDir -part $PART
if {$BOARD eq "VCK190"} {
  set_property board_part xilinx.com:vck190:part0:3.1 [current_project]
}

set_property verilog_define $VERILOG_OPTIONS [current_fileset]
puts "\n\nVERILOG DEFINES: [get_property verilog_define [current_fileset]]"

# Add VEER Headers
add_files $rtlDir/src/riscv_core/veer_el2/rtl/el2_param.vh
add_files $rtlDir/src/riscv_core/veer_el2/rtl/pic_map_auto.h
add_files $rtlDir/src/riscv_core/veer_el2/rtl/el2_pdef.vh
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/include/*.svh ]

# Add VEER sources
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/*.sv ]
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/*/*.sv ]
add_files [ glob $rtlDir/src/riscv_core/veer_el2/rtl/*/*.v ]

# Add Adam's Bridge
source adams-bridge-files.tcl

# Add Caliptra Headers
add_files [ glob $rtlDir/src/*/rtl/*.svh ]
# Add Caliptra Sources
add_files [ glob $rtlDir/src/*/rtl/*.sv ]
add_files [ glob $rtlDir/src/*/rtl/*.v ]

# Remove spi_host files that aren't used yet and are flagged as having syntax errors
# TODO: Re-include these files when spi_host is used.
remove_files [ glob $rtlDir/src/spi_host/rtl/*.sv ]

# Add FPGA specific sources
add_files [ glob $fpgaDir/src/*.sv]
add_files [ glob $fpgaDir/src/*.v]

# Replace RAM with FPGA block ram
remove_files [ glob $rtlDir/src/ecc/rtl/ecc_ram_tdp_file.sv ]

# TODO: Copy aes_clk_wrapper.sv to apply workaround
file copy [ glob $rtlDir/src/aes/rtl/aes_clp_wrapper.sv ] $outputDir/aes_clk_wrapper.sv
exec sed -i {1i `include \"kv_macros.svh\"} $outputDir/aes_clk_wrapper.sv
exec sed -i {1i `include \"caliptra_reg_field_defines.svh\"} $outputDir/aes_clk_wrapper.sv
remove_files [ glob $rtlDir/src/aes/rtl/aes_clp_wrapper.sv ]
add_files $outputDir/aes_clk_wrapper.sv

# Mark all Verilog sources as SystemVerilog because some of them have SystemVerilog syntax.
set_property file_type SystemVerilog [get_files *.v]

# Exception: caliptra_package_top.v needs to be Verilog to be included in a Block Diagram.
set_property file_type Verilog [get_files  $fpgaDir/src/caliptra_package_top.v]

# Add include paths
set_property include_dirs $rtlDir/src/integration/rtl [current_fileset]


# Set caliptra_package_top as top in case next steps fail so that the top is something useful.
if {$APB} {
  set_property top caliptra_package_apb_top [current_fileset]
} else {
  set_property top caliptra_package_axi_top [current_fileset]
}

# Create block diagram that includes an instance of caliptra_package_top
create_bd_design "caliptra_package_bd"
if {$APB} {
  create_bd_cell -type module -reference caliptra_package_apb_top caliptra_package_top_0
} else {
  create_bd_cell -type module -reference caliptra_package_axi_top caliptra_package_top_0
}
save_bd_design
close_bd_design [get_bd_designs caliptra_package_bd]

# Package IP
puts "Fileset when packaging: [current_fileset]"
puts "\n\nVERILOG DEFINES: [get_property verilog_define [current_fileset]]"
ipx::package_project -root_dir $caliptrapackageDir -vendor design -library user -taxonomy /UserIP -import_files
# Infer interfaces
ipx::infer_bus_interfaces xilinx.com:interface:apb_rtl:1.0 [ipx::current_core]
ipx::infer_bus_interfaces xilinx.com:interface:bram_rtl:1.0 [ipx::current_core]
ipx::add_bus_parameter MASTER_TYPE [ipx::get_bus_interfaces axi_bram -of_objects [ipx::current_core]]
# Associate clocks to busses
ipx::associate_bus_interfaces -busif S_AXI_WRAPPER -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif S_AXI_CALIPTRA -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif M_AXI_CALIPTRA -clock core_clk [ipx::current_core]
ipx::associate_bus_interfaces -busif axi_bram -clock axi_bram_clk [ipx::current_core]
# Other packager settings
set_property name caliptra_package_top [ipx::current_core]
set_property core_revision 1 [ipx::current_core]
set_property PAYMENT_REQUIRED FALSE [ipx::current_core]
ipx::update_source_project_archive -component [ipx::current_core]
ipx::create_xgui_files [ipx::current_core]
ipx::update_checksums [ipx::current_core]
ipx::check_integrity [ipx::current_core]
ipx::save_core [ipx::current_core]

# Close caliptra_package_project
close_project
