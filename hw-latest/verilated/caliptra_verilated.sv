// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Western Digital Corporation or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
`default_nettype none

`include "config_defines.svh"
`include "caliptra_macros.svh"

module caliptra_verilated (
    input bit core_clk,

    input bit cptra_pwrgood,
    input bit cptra_rst_b,

    // ext APT interface from C++
    input bit [`CALIPTRA_APB_ADDR_WIDTH-1:0] paddr,
    input bit [3:0] pprot,
    input bit psel,
    input bit penable,
    input bit pwrite,
    input bit [`CALIPTRA_APB_DATA_WIDTH-1:0] pwdata,
    input bit [`CALIPTRA_APB_USER_WIDTH-1:0] pauser,

    input bit ext_imem_we,
    input bit [`CALIPTRA_IMEM_ADDR_WIDTH-1:0] ext_imem_addr,
    input bit [`CALIPTRA_IMEM_DATA_WIDTH-1:0] ext_imem_wdata,

    input bit [7:0][31:0]           cptra_obf_key,

    input bit [3:0] security_state,

    // Physical Source for Internal TRNG
    input  bit [3:0]       itrng_data,
    input  bit             itrng_valid,

    input bit [3:0] sram_error_injection_mode,

    output bit ready_for_fuses,
    output bit ready_for_fw_push,

    output bit pready,
    output bit pslverr,
    output bit [`CALIPTRA_APB_DATA_WIDTH-1:0] prdata,

    output bit generic_load_en,
    output bit [31:0] generic_load_data,

    output bit etrng_req,

    output bit [31:0] uc_haddr,
    output bit [2:0] uc_hburst,
    output bit uc_hmastlock,
    output bit [3:0] uc_hprot,
    output bit [2:0] uc_hsize,
    output bit [1:0] uc_htrans,
    output bit [63:0] uc_hwdata,
    output bit uc_hwrite,

    output bit [63:0] uc_hrdata,
    output bit uc_hready,
    output bit uc_hresp

    );


    import caliptra_top_tb_pkg::*;
    import soc_ifc_pkg::*;

    logic [`CALIPTRA_IMEM_ADDR_WIDTH-1:0] imem_addr;
    logic [`CALIPTRA_IMEM_DATA_WIDTH-1:0] imem_rdata;
    logic imem_cs;

    int                         cycleCnt;
    int                         cycleCnt_Flag = '0;
    logic                       mailbox_write;
    logic                       mailbox_data_val;
    int                         commit_count;

    logic                       wb_valid;
    logic [4:0]                 wb_dest;
    logic [31:0]                wb_data;


    string                      abi_reg[32]; // ABI register names

    logic mbox_sram_cs;
    logic mbox_sram_we;
    logic [14:0] mbox_sram_addr;
    logic [MBOX_DATA_AND_ECC_W-1:0] mbox_sram_wdata;
    logic [MBOX_DATA_AND_ECC_W-1:0] mbox_sram_wdata_bitflip;
    logic [MBOX_DATA_AND_ECC_W-1:0] mbox_sram_rdata;

    el2_mem_if el2_mem_export ();


    initial begin
    end

   //=========================================================================-
   // DUT instance
   //=========================================================================-
caliptra_top caliptra_top_dut (
    .cptra_pwrgood              (cptra_pwrgood),
    .cptra_rst_b                (cptra_rst_b),
    .clk                        (core_clk),

    .cptra_obf_key              (cptra_obf_key),

    .jtag_tck(1'b0),
    .jtag_tdi(1'b0),
    .jtag_tms(1'b0),
    .jtag_trst_n(1'b0),
    .jtag_tdo(),

    .PADDR(paddr),
    .PPROT(),
    .PAUSER(pauser),
    .PENABLE(penable),
    .PRDATA(prdata),
    .PREADY(pready),
    .PSEL(psel),
    .PSLVERR(),
    .PWDATA(pwdata),
    .PWRITE(pwrite),

    .qspi_clk_o(),
    .qspi_cs_no(),
    .qspi_d_i(4'b0),
    .qspi_d_o(),
    .qspi_d_en_o(),

    .el2_mem_export(el2_mem_export),

    .ready_for_fuses(ready_for_fuses),
    .ready_for_fw_push(ready_for_fw_push),
    .ready_for_runtime(),

    .mbox_sram_cs(mbox_sram_cs),
    .mbox_sram_we(mbox_sram_we),
    .mbox_sram_addr(mbox_sram_addr),
    .mbox_sram_wdata(mbox_sram_wdata),
    .mbox_sram_rdata(mbox_sram_rdata),

    .imem_cs(imem_cs),
    .imem_addr(imem_addr),
    .imem_rdata(imem_rdata),

    .mailbox_data_avail(),
    .mailbox_flow_done(),
    .BootFSM_BrkPoint('x), //FIXME TIE-OFF

    .generic_input_wires('x), //FIXME TIE-OFF
    .generic_output_wires(),

    .scan_mode(),

    //FIXME: export these
    .cptra_error_fatal(),
    .cptra_error_non_fatal(),
    .etrng_req(etrng_req),
    .itrng_data(itrng_data),
    .itrng_valid(itrng_valid),

    .security_state(security_state)
);

assign generic_load_en = caliptra_top_dut.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.load_next;
assign generic_load_data = caliptra_top_dut.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.next;

assign uc_haddr = caliptra_top_dut.rvtop.lsu_haddr;
assign uc_hburst = caliptra_top_dut.rvtop.lsu_hburst;
assign uc_hmastlock = caliptra_top_dut.rvtop.lsu_hmastlock;
assign uc_hprot = caliptra_top_dut.rvtop.lsu_hprot;
assign uc_hsize = caliptra_top_dut.rvtop.lsu_hsize;
assign uc_htrans = caliptra_top_dut.rvtop.lsu_htrans;
assign uc_hwdata = caliptra_top_dut.rvtop.lsu_hwdata;
assign uc_hwrite = caliptra_top_dut.rvtop.lsu_hwrite;

assign uc_hrdata = caliptra_top_dut.rvtop.lsu_hrdata;
assign uc_hready = caliptra_top_dut.rvtop.lsu_hready;
assign uc_hresp = caliptra_top_dut.rvtop.lsu_hresp;

// Decode:
//  [0] - Single bit, ICCM Error Injection
//  [1] - Double bit, ICCM Error Injection
//  [2] - Single bit, DCCM Error Injection
//  [3] - Double bit, DCCM Error Injection
veer_sram_error_injection_mode_t veer_sram_error_injection_mode;
assign veer_sram_error_injection_mode.iccm_single_bit_error = sram_error_injection_mode[0];
assign veer_sram_error_injection_mode.iccm_double_bit_error = sram_error_injection_mode[1];
assign veer_sram_error_injection_mode.dccm_single_bit_error = sram_error_injection_mode[2];
assign veer_sram_error_injection_mode.dccm_double_bit_error = sram_error_injection_mode[3];

caliptra_veer_sram_export veer_sram_export_inst (
    .sram_error_injection_mode(sram_error_injection_mode),
    .el2_mem_export(el2_mem_export.top)
);

//SRAM for mbox (preload raw data here)
caliptra_sram
#(
    .DATA_WIDTH(MBOX_DATA_W),
    .DEPTH     (MBOX_DEPTH )
)
dummy_mbox_preloader
(
    .clk_i(core_clk),

    .cs_i   (),
    .we_i   (),
    .addr_i (),
    .wdata_i(),
    .rdata_o()
);
// Actual Mailbox RAM -- preloaded with data from
// dummy_mbox_preloader with ECC bits appended
caliptra_sram
#(
    .DATA_WIDTH(MBOX_DATA_AND_ECC_W),
    .DEPTH     (MBOX_DEPTH         )
)
mbox_ram1
(
    .clk_i(core_clk),

    .cs_i(mbox_sram_cs),
    .we_i(mbox_sram_we),
    .addr_i(mbox_sram_addr),
    .wdata_i(mbox_sram_wdata ^ mbox_sram_wdata_bitflip),

    .rdata_o(mbox_sram_rdata)
);

//SRAM for imem
caliptra_sram #(
    .DEPTH     (`CALIPTRA_IMEM_DEPTH     ), // Depth in WORDS
    .DATA_WIDTH(`CALIPTRA_IMEM_DATA_WIDTH),
    .ADDR_WIDTH(`CALIPTRA_IMEM_ADDR_WIDTH)
) imem_inst1 (
    .clk_i   (core_clk   ),

    .cs_i    (imem_cs | ext_imem_we),
    .we_i    (ext_imem_we),
    .addr_i  (ext_imem_we ? ext_imem_addr : imem_addr),
    .wdata_i (ext_imem_wdata),
    .rdata_o (imem_rdata                         )
);

// This is used to load the generated ICCM hexfile prior to
// running slam_iccm_ram
caliptra_sram #(
     .DEPTH     (16384        ), // 128KiB
     .DATA_WIDTH(64           ),
     .ADDR_WIDTH($clog2(16384))

) dummy_iccm_preloader (
    .clk_i   (core_clk),

    .cs_i    (        ),
    .we_i    (        ),
    .addr_i  (        ),
    .wdata_i (        ),
    .rdata_o (        )
);


// This is used to load the generated DCCM hexfile prior to
// running slam_dccm_ram
caliptra_sram #(
     .DEPTH     (16384        ), // 128KiB
     .DATA_WIDTH(64           ),
     .ADDR_WIDTH($clog2(16384))

) dummy_dccm_preloader (
    .clk_i   (core_clk),

    .cs_i    (        ),
    .we_i    (        ),
    .addr_i  (        ),
    .wdata_i (        ),
    .rdata_o (        )
);

endmodule
