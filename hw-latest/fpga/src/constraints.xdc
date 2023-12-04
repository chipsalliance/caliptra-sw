connect_debug_port u_ila_0/probe9 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[control][cptra_rst_b][value]}]]


connect_debug_port u_ila_0/probe9 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[control][cptra_pwrgood][value]}]]
connect_debug_port u_ila_0/probe10 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/regs/hwif_out[control][cptra_rst_b][value]}]]


set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][7]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][6]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][5]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][4]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][3]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][2]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][1]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][0]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][log_fifo_data][next_char][rd_swacc]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][load_next]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_status][log_fifo_full][next]}]
set_property MARK_DEBUG true [get_nets {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_status][log_fifo_empty][next]}]
connect_debug_port u_ila_0/probe18 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][log_fifo_data][next_char][rd_swacc]}]]


create_debug_core u_ila_0 ila
set_property ALL_PROBE_SAME_MU true [get_debug_cores u_ila_0]
set_property ALL_PROBE_SAME_MU_CNT 1 [get_debug_cores u_ila_0]
set_property C_ADV_TRIGGER false [get_debug_cores u_ila_0]
set_property C_DATA_DEPTH 1024 [get_debug_cores u_ila_0]
set_property C_EN_STRG_QUAL false [get_debug_cores u_ila_0]
set_property C_INPUT_PIPE_STAGES 0 [get_debug_cores u_ila_0]
set_property C_TRIGIN_EN false [get_debug_cores u_ila_0]
set_property C_TRIGOUT_EN false [get_debug_cores u_ila_0]
set_property port_width 1 [get_debug_ports u_ila_0/clk]
connect_debug_port u_ila_0/clk [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0/inst/pl_clk0]]
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe0]
set_property port_width 32 [get_debug_ports u_ila_0/probe0]
connect_debug_port u_ila_0/probe0 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[17]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[18]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[19]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[20]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[21]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[22]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[23]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[24]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[25]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[26]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[27]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[28]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[29]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[30]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RDATA[31]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe1]
set_property port_width 31 [get_debug_ports u_ila_0/probe1]
connect_debug_port u_ila_0/probe1 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[17]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[18]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[19]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[20]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[21]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[22]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[23]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[24]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[25]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[26]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[27]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[28]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[29]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[30]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/rvtop/veer/ifu_i0_pc[31]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe2]
set_property port_width 4 [get_debug_ports u_ila_0/probe2]
connect_debug_port u_ila_0/probe2 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/itrng_data[0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/itrng_data[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/itrng_data[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/itrng_data[3]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe3]
set_property port_width 32 [get_debug_ports u_ila_0/probe3]
connect_debug_port u_ila_0/probe3 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][17]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][18]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][19]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][20]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][21]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][22]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][23]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][24]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][25]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][26]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][27]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][28]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][29]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][30]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][value][31]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe4]
set_property port_width 8 [get_debug_ports u_ila_0/probe4]
connect_debug_port u_ila_0/probe4 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_data][next_char][next][7]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe5]
set_property port_width 32 [get_debug_ports u_ila_0/probe5]
connect_debug_port u_ila_0/probe5 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[17]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[18]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[19]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[20]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[21]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[22]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[23]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[24]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[25]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[26]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[27]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[28]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[29]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[30]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_prdata[31]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe6]
set_property port_width 18 [get_debug_ports u_ila_0/probe6]
connect_debug_port u_ila_0/probe6 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_paddr[17]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe7]
set_property port_width 5 [get_debug_ports u_ila_0/probe7]
connect_debug_port u_ila_0/probe7 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARADDR[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARADDR[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARADDR[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARADDR[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARADDR[6]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe8]
set_property port_width 5 [get_debug_ports u_ila_0/probe8]
connect_debug_port u_ila_0/probe8 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWADDR[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWADDR[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWADDR[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWADDR[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWADDR[6]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe9]
set_property port_width 8 [get_debug_ports u_ila_0/probe9]
connect_debug_port u_ila_0/probe9 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][next][7]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe10]
set_property port_width 32 [get_debug_ports u_ila_0/probe10]
connect_debug_port u_ila_0/probe10 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[17]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[18]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[19]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[20]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[21]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[22]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[23]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[24]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[25]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[26]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[27]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[28]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[29]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[30]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WDATA[31]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe11]
set_property port_width 32 [get_debug_ports u_ila_0/probe11]
connect_debug_port u_ila_0/probe11 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[0]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[1]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[2]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[3]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[4]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[5]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[6]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[7]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[8]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[9]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[10]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[11]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[12]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[13]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[14]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[15]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[16]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[17]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[18]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[19]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[20]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[21]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[22]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[23]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[24]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[25]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[26]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[27]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[28]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[29]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[30]} {caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwdata[31]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe12]
set_property port_width 1 [get_debug_ports u_ila_0/probe12]
connect_debug_port u_ila_0/probe12 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/field_combo[CPTRA_GENERIC_OUTPUT_WIRES][0][generic_wires][load_next]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe13]
set_property port_width 1 [get_debug_ports u_ila_0/probe13]
connect_debug_port u_ila_0/probe13 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/caliptra_top_dut/soc_ifc_top1/i_soc_ifc_boot_fsm/fsm_synch_noncore_rst_b]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe14]
set_property port_width 1 [get_debug_ports u_ila_0/probe14]
connect_debug_port u_ila_0/probe14 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][itrng_fifo_status][itrng_fifo_empty][next]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe15]
set_property port_width 1 [get_debug_ports u_ila_0/probe15]
connect_debug_port u_ila_0/probe15 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][itrng_fifo_status][itrng_fifo_full][next]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe16]
set_property port_width 1 [get_debug_ports u_ila_0/probe16]
connect_debug_port u_ila_0/probe16 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_status][log_fifo_empty][next]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe17]
set_property port_width 1 [get_debug_ports u_ila_0/probe17]
connect_debug_port u_ila_0/probe17 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_in[fifo_regs][log_fifo_status][log_fifo_full][next]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe18]
set_property port_width 1 [get_debug_ports u_ila_0/probe18]
connect_debug_port u_ila_0/probe18 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/hwif_out[fifo_regs][itrng_fifo_data][itrng_data][wr_swacc]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe19]
set_property port_width 1 [get_debug_ports u_ila_0/probe19]
connect_debug_port u_ila_0/probe19 [get_nets [list {caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/regs/hwif_out[interface_regs][control][cptra_rst_b][value]}]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe20]
set_property port_width 1 [get_debug_ports u_ila_0/probe20]
connect_debug_port u_ila_0/probe20 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/itrng_valid]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe21]
set_property port_width 1 [get_debug_ports u_ila_0/probe21]
connect_debug_port u_ila_0/probe21 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_penable]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe22]
set_property port_width 1 [get_debug_ports u_ila_0/probe22]
connect_debug_port u_ila_0/probe22 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pready]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe23]
set_property port_width 1 [get_debug_ports u_ila_0/probe23]
connect_debug_port u_ila_0/probe23 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_psel]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe24]
set_property port_width 1 [get_debug_ports u_ila_0/probe24]
connect_debug_port u_ila_0/probe24 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pslverr]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe25]
set_property port_width 1 [get_debug_ports u_ila_0/probe25]
connect_debug_port u_ila_0/probe25 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/s_apb_pwrite]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe26]
set_property port_width 1 [get_debug_ports u_ila_0/probe26]
connect_debug_port u_ila_0/probe26 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARREADY]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe27]
set_property port_width 1 [get_debug_ports u_ila_0/probe27]
connect_debug_port u_ila_0/probe27 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_ARVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe28]
set_property port_width 1 [get_debug_ports u_ila_0/probe28]
connect_debug_port u_ila_0/probe28 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWREADY]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe29]
set_property port_width 1 [get_debug_ports u_ila_0/probe29]
connect_debug_port u_ila_0/probe29 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_AWVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe30]
set_property port_width 1 [get_debug_ports u_ila_0/probe30]
connect_debug_port u_ila_0/probe30 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_BREADY]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe31]
set_property port_width 1 [get_debug_ports u_ila_0/probe31]
connect_debug_port u_ila_0/probe31 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_BVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe32]
set_property port_width 1 [get_debug_ports u_ila_0/probe32]
connect_debug_port u_ila_0/probe32 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RREADY]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe33]
set_property port_width 1 [get_debug_ports u_ila_0/probe33]
connect_debug_port u_ila_0/probe33 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_RVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe34]
set_property port_width 1 [get_debug_ports u_ila_0/probe34]
connect_debug_port u_ila_0/probe34 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WREADY]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe35]
set_property port_width 1 [get_debug_ports u_ila_0/probe35]
connect_debug_port u_ila_0/probe35 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/S_AXI_WVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe36]
set_property port_width 1 [get_debug_ports u_ila_0/probe36]
connect_debug_port u_ila_0/probe36 [get_nets [list caliptra_fpga_project_bd_i/caliptra_package_top_0/inst/cptra_wrapper/throttled_etrng_req]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe37]
set_property port_width 1 [get_debug_ports u_ila_0/probe37]
connect_debug_port u_ila_0/probe37 [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0_M_AXI_HPM0_LPD_ARVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe38]
set_property port_width 1 [get_debug_ports u_ila_0/probe38]
connect_debug_port u_ila_0/probe38 [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0_M_AXI_HPM0_LPD_AWVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe39]
set_property port_width 1 [get_debug_ports u_ila_0/probe39]
connect_debug_port u_ila_0/probe39 [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0_M_AXI_HPM0_LPD_BVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe40]
set_property port_width 1 [get_debug_ports u_ila_0/probe40]
connect_debug_port u_ila_0/probe40 [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0_M_AXI_HPM0_LPD_RVALID]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe41]
set_property port_width 1 [get_debug_ports u_ila_0/probe41]
connect_debug_port u_ila_0/probe41 [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0_M_AXI_HPM0_LPD_WLAST]]
create_debug_port u_ila_0 probe
set_property PROBE_TYPE DATA_AND_TRIGGER [get_debug_ports u_ila_0/probe42]
set_property port_width 1 [get_debug_ports u_ila_0/probe42]
connect_debug_port u_ila_0/probe42 [get_nets [list caliptra_fpga_project_bd_i/zynq_ultra_ps_e_0_M_AXI_HPM0_LPD_WVALID]]
set_property C_CLK_INPUT_FREQ_HZ 300000000 [get_debug_cores dbg_hub]
set_property C_ENABLE_CLK_DIVIDER false [get_debug_cores dbg_hub]
set_property C_USER_SCAN_CHAIN 1 [get_debug_cores dbg_hub]
connect_debug_port dbg_hub/clk [get_nets u_ila_0_pl_clk0]
