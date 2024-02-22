`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 03/21/2023 11:49:47 AM
// Design Name:
// Module Name: caliptra_package_top
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
//
// Dependencies:
//
// Revision:
// Revision 0.01 - File Created
// Additional Comments: Vivado does not support using a SystemVerilog as the top level file in an package.
//
//////////////////////////////////////////////////////////////////////////////////

`default_nettype wire

`define CALIPTRA_APB_ADDR_WIDTH      32 // bit-width APB address
`define CALIPTRA_APB_DATA_WIDTH      32 // bit-width APB data

module caliptra_package_top (
    input wire core_clk,

    // Caliptra APB Interface
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

    // ROM AXI Interface
    input  wire                       axi_bram_clk,
    input  wire                       axi_bram_en,
    input  wire [3:0]                 axi_bram_we,
    input  wire [15:0]                axi_bram_addr,
    input  wire [31:0]                axi_bram_din,
    output wire [31:0]                axi_bram_dout,
    input  wire                       axi_bram_rst,

    // JTAG Interface
    input wire                        jtag_tck,    // JTAG clk
    input wire                        jtag_tms,    // JTAG tms
    input wire                        jtag_tdi,    // JTAG tdi
    input wire                        jtag_trst_n, // JTAG reset
    output wire                       jtag_tdo,    // JTAG tdo

    // FPGA Realtime register AXI Interface
    input	wire                      S_AXI_ARESETN,
    input	wire                      S_AXI_AWVALID,
    output	wire                      S_AXI_AWREADY,
    input	wire [31:0]               S_AXI_AWADDR,
    input	wire [2:0]                S_AXI_AWPROT,
    input	wire                      S_AXI_WVALID,
    output	wire                      S_AXI_WREADY,
    input	wire [31:0]               S_AXI_WDATA,
    input	wire [3:0]                S_AXI_WSTRB,
    output	wire                      S_AXI_BVALID,
    input	wire                      S_AXI_BREADY,
    output	wire [1:0]                S_AXI_BRESP,
    input	wire                      S_AXI_ARVALID,
    output	wire                      S_AXI_ARREADY,
    input	wire [31:0]               S_AXI_ARADDR,
    input	wire [2:0]                S_AXI_ARPROT,
    output	wire                      S_AXI_RVALID,
    input	wire                      S_AXI_RREADY,
    output	wire [31:0]               S_AXI_RDATA,
    output	wire [1:0]                S_AXI_RRESP
    );

caliptra_wrapper_top cptra_wrapper (
    .core_clk(core_clk),

    .PADDR(s_apb_paddr[`CALIPTRA_APB_ADDR_WIDTH-1:0]),
    .PPROT(s_apb_pprot),
    .PENABLE(s_apb_penable),
    .PRDATA(s_apb_prdata),
    .PREADY(s_apb_pready),
    .PSEL(s_apb_psel),
    .PSLVERR(s_apb_pslverr),
    .PWDATA(s_apb_pwdata),
    .PWRITE(s_apb_pwrite),

    // SOC access to program ROM
    .axi_bram_clk(axi_bram_clk),
    .axi_bram_en(axi_bram_en),
    .axi_bram_we(axi_bram_we),
    .axi_bram_addr(axi_bram_addr[15:2]),
    .axi_bram_wrdata(axi_bram_din),
    .axi_bram_rddata(axi_bram_dout),
    .axi_bram_rst(axi_bram_rst),

    // EL2 JTAG interface
    .jtag_tck(jtag_tck),
    .jtag_tdi(jtag_tdi),
    .jtag_tms(jtag_tms),
    .jtag_trst_n(jtag_trst_n),
    .jtag_tdo(jtag_tdo),

    // FPGA Realtime register AXI Interface
    .S_AXI_ARESETN(S_AXI_ARESETN),
    .S_AXI_AWVALID(S_AXI_AWVALID),
    .S_AXI_AWREADY(S_AXI_AWREADY),
    .S_AXI_AWADDR(S_AXI_AWADDR),
    .S_AXI_AWPROT(S_AXI_AWPROT),
    .S_AXI_WVALID(S_AXI_WVALID),
    .S_AXI_WREADY(S_AXI_WREADY),
    .S_AXI_WDATA(S_AXI_WDATA),
    .S_AXI_WSTRB(S_AXI_WSTRB),
    .S_AXI_BVALID(S_AXI_BVALID),
    .S_AXI_BREADY(S_AXI_BREADY),
    .S_AXI_BRESP(S_AXI_BRESP),
    .S_AXI_ARVALID(S_AXI_ARVALID),
    .S_AXI_ARREADY(S_AXI_ARREADY),
    .S_AXI_ARADDR(S_AXI_ARADDR),
    .S_AXI_ARPROT(S_AXI_ARPROT),
    .S_AXI_RVALID(S_AXI_RVALID),
    .S_AXI_RREADY(S_AXI_RREADY),
    .S_AXI_RDATA(S_AXI_RDATA),
    .S_AXI_RRESP(S_AXI_RRESP)
);

endmodule
