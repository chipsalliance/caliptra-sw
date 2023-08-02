`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 03/21/2023 11:49:47 AM
// Design Name:
// Module Name: fpga_top
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
//
// Dependencies:
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
//
//////////////////////////////////////////////////////////////////////////////////

`default_nettype wire

`define CALIPTRA_APB_ADDR_WIDTH      32 // bit-width APB address
`define CALIPTRA_APB_DATA_WIDTH      32 // bit-width APB data
`define CALIPTRA_APB_USER_WIDTH      32 // bit-width APB PAUSER field

`define CALIPTRA_IMEM_BYTE_SIZE   32768
`define CALIPTRA_IMEM_DATA_WIDTH  64
`define CALIPTRA_IMEM_DEPTH       `CALIPTRA_IMEM_BYTE_SIZE / (`CALIPTRA_IMEM_DATA_WIDTH/8)
`define CALIPTRA_IMEM_BYTE_ADDR_W $clog2(`CALIPTRA_IMEM_BYTE_SIZE)
`define CALIPTRA_IMEM_ADDR_WIDTH  $clog2(`CALIPTRA_IMEM_DEPTH)

module caliptra_package_top (
    input wire core_clk,

    input  wire [31:0] gpio_in,
    output wire [31:0] gpio_out,
    input wire [255:0] cptra_obf_key,

    output wire [7:0] fifo_char,
    output wire fifo_write_en,

    //APB Interface
    input  wire [39:0]                s_apb_paddr,
    input  wire                       s_apb_penable,
    input  wire [2:0]                 s_apb_pprot,
    output wire [`CALIPTRA_APB_DATA_WIDTH-1:0] s_apb_prdata,
    output wire                       s_apb_pready,
    input  wire                       s_apb_psel,
    output wire                       s_apb_pslverr,
    input  wire [3:0]                 s_apb_pstrb, // Leave unconnected
    input  wire [`CALIPTRA_APB_DATA_WIDTH-1:0] s_apb_pwdata,
    input  wire                       s_apb_pwrite,

    input  wire [`CALIPTRA_APB_USER_WIDTH-1:0] pauser,

    input  wire axi_bram_clk,
    input  wire axi_bram_en,
    input  wire [3:0] axi_bram_we,
    input  wire [14:0] axi_bram_addr, // 12:0
    input  wire [31:0] axi_bram_din,
    output wire [31:0] axi_bram_dout,
    input  wire axi_bram_rst,


    //JTAG Interface
    input wire                        jtag_tck,    // JTAG clk
    input wire                        jtag_tms,    // JTAG tms
    input wire                        jtag_tdi,    // JTAG tdi
    input wire                        jtag_trst_n, // JTAG reset
    output wire                       jtag_tdo     // JTAG tdo
    );

    // Unused bits of soc adapter register
    assign gpio_out[31] = 1'b0;
    assign gpio_out[25:0] = 26'h0;

    wire [63:0] generic_output_wires;

    // Hierarchical references to generic output wires register. Use as input to log FIFO.
    assign fifo_write_en = cptra_wrapper.caliptra_top_dut.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.load_next;
    assign fifo_char[7:0] = cptra_wrapper.caliptra_top_dut.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.next[7:0];


caliptra_wrapper_top cptra_wrapper (
    .core_clk(core_clk),

    .PADDR(s_apb_paddr[`CALIPTRA_APB_ADDR_WIDTH-1:0]),
    .PPROT(s_apb_pprot),
    .PAUSER(pauser),
    .PENABLE(s_apb_penable),
    .PRDATA(s_apb_prdata),
    .PREADY(s_apb_pready),
    .PSEL(s_apb_psel),
    .PSLVERR(s_apb_pslverr),
    .PWDATA(s_apb_pwdata),
    .PWRITE(s_apb_pwrite),

    .cptra_obf_key(cptra_obf_key),

    // SOC signals connected to GPIO
    .cptra_pwrgood              (gpio_in[1]),
    .cptra_rst_b                (gpio_in[0]),
    .ready_for_fuses            (gpio_out[30]),
    .ready_for_runtime          (gpio_out[29]),
    .ready_for_fw_push          (gpio_out[28]),

    // Security state
    .debug_locked(gpio_in[6]),
    .device_lifecycle(gpio_in[5:4]),

    // Error signals
    .cptra_error_fatal(gpio_out[26]),
    .cptra_error_non_fatal(gpio_out[27]),

    .generic_input_wires(),
    .generic_output_wires(generic_output_wires),

    // SOC access to program ROM
    .axi_bram_clk(axi_bram_clk),
    .axi_bram_en(axi_bram_en),
    .axi_bram_we(axi_bram_we),
    .axi_bram_addr(axi_bram_addr[14:2]),
    .axi_bram_wrdata(axi_bram_din),
    .axi_bram_rddata(axi_bram_dout),
    .axi_bram_rst(axi_bram_rst),

    // EL2 JTAG interface
    .jtag_tck(jtag_tck),
    .jtag_tdi(jtag_tdi),
    .jtag_tms(jtag_tms),
    .jtag_trst_n(jtag_trst_n),
    .jtag_tdo(jtag_tdo)
);

endmodule
