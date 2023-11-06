// SPDX-License-Identifier: Apache-2.0
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
`default_nettype wire

`include "common_defines.sv"
`include "config_defines.svh"
`include "caliptra_reg_defines.svh"
`include "caliptra_macros.svh"

module caliptra_wrapper_top (
    input bit cptra_pwrgood,
    input bit cptra_rst_b,
    input bit core_clk,

    output bit ready_for_fuses,
    output bit ready_for_fw_push,
    output bit ready_for_runtime,
    
    //APB Interface
    input  wire [`CALIPTRA_APB_ADDR_WIDTH-1:0] PADDR,
    input  wire                       PENABLE,
    input  wire [2:0]                 PPROT,
    output wire [`CALIPTRA_APB_DATA_WIDTH-1:0] PRDATA,
    output wire                       PREADY,
    input  wire                       PSEL,
    output wire                       PSLVERR,
    input  wire [`CALIPTRA_APB_DATA_WIDTH-1:0] PWDATA,
    input  wire                       PWRITE,
    input  wire [`CALIPTRA_APB_USER_WIDTH-1:0] PAUSER,

    input wire [255:0]           cptra_obf_key,

    //device lifecycle
    input wire debug_locked,
    input wire [1:0] device_lifecycle,

    input wire cptra_error_fatal,
    input wire cptra_error_non_fatal,

    input  wire [63:0] generic_input_wires,
    output wire [63:0] generic_output_wires,

    // Access for AXI to program rom
    input  logic axi_bram_clk,
    input  logic axi_bram_en,
    input  logic [3:0] axi_bram_we,
    input  logic [13:0] axi_bram_addr,
    input  logic [31:0] axi_bram_wrdata,
    output logic [31:0] axi_bram_rddata,
    input  logic axi_bram_rst,

    //JTAG Interface
    input logic                        jtag_tck,    // JTAG clk
    input logic                        jtag_tms,    // JTAG tms
    input logic                        jtag_tdi,    // JTAG tdi
    input logic                        jtag_trst_n, // JTAG reset
    output logic                       jtag_tdo     // JTAG tdo
    );

    import soc_ifc_pkg::*;

    logic                       BootFSM_BrkPoint;

    //logic ready_for_fuses;
    logic mbox_sram_cs;
    logic mbox_sram_we;
    logic [14:0] mbox_sram_addr;
    logic [MBOX_DATA_AND_ECC_W-1:0] mbox_sram_wdata;
    logic [MBOX_DATA_AND_ECC_W-1:0] mbox_sram_rdata;

    logic imem_cs;
    logic [`CALIPTRA_IMEM_ADDR_WIDTH-1:0] imem_addr;
    logic [`CALIPTRA_IMEM_DATA_WIDTH-1:0] imem_rdata;


    security_state_t security_state;
    assign security_state = '{device_lifecycle: device_lifecycle_e'(device_lifecycle), debug_locked: debug_locked};

    el2_mem_if el2_mem_export ();

    initial begin
        BootFSM_BrkPoint = 1'b1; //Set to 1 even before anything starts
    end

`ifdef CALIPTRA_INTERNAL_TRNG
    logic itrng_valid;
    logic [3:0]itrng_data;
`endif

//=========================================================================-
// DUT instance
//=========================================================================-
caliptra_top caliptra_top_dut (
    .cptra_pwrgood              (cptra_pwrgood),
    .cptra_rst_b                (cptra_rst_b),
    .clk                        (core_clk),

    .cptra_obf_key              (cptra_obf_key),

    .jtag_tck(jtag_tck),
    .jtag_tdi(jtag_tdi),
    .jtag_tms(jtag_tms),
    .jtag_trst_n(jtag_trst_n),
    .jtag_tdo(jtag_tdo),

    .PADDR(PADDR),
    .PPROT(PPROT), // TODO: PPROT not provided?
    .PAUSER(PAUSER),
    .PENABLE(PENABLE),
    .PRDATA(PRDATA),
    .PREADY(PREADY),
    .PSEL(PSEL),
    .PSLVERR(PSLVERR),
    .PWDATA(PWDATA),
    .PWRITE(PWRITE),

    .qspi_clk_o (),
    .qspi_cs_no (),
    .qspi_d_i   (),
    .qspi_d_o   (),
    .qspi_d_en_o(),

    .el2_mem_export(el2_mem_export),

    .ready_for_fuses(ready_for_fuses),
    .ready_for_fw_push(ready_for_fw_push),
    .ready_for_runtime(ready_for_runtime),

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
    .BootFSM_BrkPoint(BootFSM_BrkPoint),

    //SoC Interrupts
    .cptra_error_fatal    (cptra_error_fatal),
    .cptra_error_non_fatal(cptra_error_non_fatal),

`ifdef CALIPTRA_INTERNAL_TRNG
    .etrng_req             (etrng_req),
    .itrng_data            (itrng_data),
    .itrng_valid           (itrng_valid),
`else
    .etrng_req             (),
    .itrng_data            (4'b0),
    .itrng_valid           (1'b0),
`endif
    //.trng_req(),

    .generic_input_wires(generic_input_wires),
    .generic_output_wires(generic_output_wires),

    .security_state(security_state), //FIXME TIE-OFF
    .scan_mode     (scan_mode) //FIXME TIE-OFF
);


// EL2 Memory
caliptra_veer_sram_export veer_sram_export_inst (
    .el2_mem_export(el2_mem_export)
);

// Mailbox RAM
fpga_mbox_ram mbox_ram1
(
    .clka(core_clk),

    .ena(mbox_sram_cs),
    .wea(mbox_sram_we),
    .addra(mbox_sram_addr),
    .dina(mbox_sram_wdata),

    .douta(mbox_sram_rdata)
);

// SRAM for imem/ROM
fpga_imem imem_inst1(
    // Port A for Caliptra
    .clka(core_clk),
    .ena(imem_cs),
    .wea(8'h0),
    .addra(imem_addr),
    .dina(0),
    .douta(imem_rdata),
    // Port B to the AXI bus for loading ROM
    .clkb(axi_bram_clk),
    .enb(axi_bram_en),
    .web(axi_bram_we),
    .addrb(axi_bram_addr),
    .dinb(axi_bram_wrdata),
    .doutb(axi_bram_rddata),
    .rstb(axi_bram_rst)
);

endmodule
