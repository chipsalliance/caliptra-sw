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

module caliptra_package_apb_top (
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
    input  wire [16:0]                axi_bram_addr,
    input  wire [31:0]                axi_bram_din,
    output wire [31:0]                axi_bram_dout,
    input  wire                       axi_bram_rst,

    // JTAG Interface
    input wire [4:0]                  jtag_in,     // JTAG input signals concatenated
    output wire [4:0]                 jtag_out,    // JTAG tdo

    // FPGA Realtime register AXI Interface
    input	wire                      S_AXI_WRAPPER_ARESETN,
    input	wire                      S_AXI_WRAPPER_AWVALID,
    output	wire                      S_AXI_WRAPPER_AWREADY,
    input	wire [31:0]               S_AXI_WRAPPER_AWADDR,
    input	wire [2:0]                S_AXI_WRAPPER_AWPROT,
    input	wire                      S_AXI_WRAPPER_WVALID,
    output	wire                      S_AXI_WRAPPER_WREADY,
    input	wire [31:0]               S_AXI_WRAPPER_WDATA,
    input	wire [3:0]                S_AXI_WRAPPER_WSTRB,
    output	wire                      S_AXI_WRAPPER_BVALID,
    input	wire                      S_AXI_WRAPPER_BREADY,
    output	wire [1:0]                S_AXI_WRAPPER_BRESP,
    input	wire                      S_AXI_WRAPPER_ARVALID,
    output	wire                      S_AXI_WRAPPER_ARREADY,
    input	wire [31:0]               S_AXI_WRAPPER_ARADDR,
    input	wire [2:0]                S_AXI_WRAPPER_ARPROT,
    output	wire                      S_AXI_WRAPPER_RVALID,
    input	wire                      S_AXI_WRAPPER_RREADY,
    output	wire [31:0]               S_AXI_WRAPPER_RDATA,
    output	wire [1:0]                S_AXI_WRAPPER_RRESP
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
    .axi_bram_addr(axi_bram_addr[16:2]),
    .axi_bram_wrdata(axi_bram_din),
    .axi_bram_rddata(axi_bram_dout),
    .axi_bram_rst(axi_bram_rst),

    // EL2 JTAG interface
    .jtag_tck(jtag_in[0]),
    .jtag_tdi(jtag_in[1]),
    .jtag_tms(jtag_in[2]),
    .jtag_trst_n(jtag_in[3]),
    .jtag_tdo(jtag_out[4]),

    // FPGA Realtime register AXI Interface
    .S_AXI_WRAPPER_ARESETN(S_AXI_WRAPPER_ARESETN),
    .S_AXI_WRAPPER_AWVALID(S_AXI_WRAPPER_AWVALID),
    .S_AXI_WRAPPER_AWREADY(S_AXI_WRAPPER_AWREADY),
    .S_AXI_WRAPPER_AWADDR(S_AXI_WRAPPER_AWADDR),
    .S_AXI_WRAPPER_AWPROT(S_AXI_WRAPPER_AWPROT),
    .S_AXI_WRAPPER_WVALID(S_AXI_WRAPPER_WVALID),
    .S_AXI_WRAPPER_WREADY(S_AXI_WRAPPER_WREADY),
    .S_AXI_WRAPPER_WDATA(S_AXI_WRAPPER_WDATA),
    .S_AXI_WRAPPER_WSTRB(S_AXI_WRAPPER_WSTRB),
    .S_AXI_WRAPPER_BVALID(S_AXI_WRAPPER_BVALID),
    .S_AXI_WRAPPER_BREADY(S_AXI_WRAPPER_BREADY),
    .S_AXI_WRAPPER_BRESP(S_AXI_WRAPPER_BRESP),
    .S_AXI_WRAPPER_ARVALID(S_AXI_WRAPPER_ARVALID),
    .S_AXI_WRAPPER_ARREADY(S_AXI_WRAPPER_ARREADY),
    .S_AXI_WRAPPER_ARADDR(S_AXI_WRAPPER_ARADDR),
    .S_AXI_WRAPPER_ARPROT(S_AXI_WRAPPER_ARPROT),
    .S_AXI_WRAPPER_RVALID(S_AXI_WRAPPER_RVALID),
    .S_AXI_WRAPPER_RREADY(S_AXI_WRAPPER_RREADY),
    .S_AXI_WRAPPER_RDATA(S_AXI_WRAPPER_RDATA),
    .S_AXI_WRAPPER_RRESP(S_AXI_WRAPPER_RRESP)
);

endmodule
module caliptra_package_axi_top (
    input wire core_clk,

    // Caliptra AXI Interface
    input  wire [31:0] S_AXI_CALIPTRA_AWADDR,
    input  wire [1:0] S_AXI_CALIPTRA_AWBURST,
    input  wire [2:0] S_AXI_CALIPTRA_AWSIZE,
    input  wire [7:0] S_AXI_CALIPTRA_AWLEN,
    input  wire [31:0] S_AXI_CALIPTRA_AWUSER,
    input  wire [15:0] S_AXI_CALIPTRA_AWID,
    input  wire S_AXI_CALIPTRA_AWLOCK,
    input  wire S_AXI_CALIPTRA_AWVALID,
    output wire S_AXI_CALIPTRA_AWREADY,
    // W
    input  wire [31:0] S_AXI_CALIPTRA_WDATA,
    input  wire [3:0] S_AXI_CALIPTRA_WSTRB,
    input  wire S_AXI_CALIPTRA_WVALID,
    output wire S_AXI_CALIPTRA_WREADY,
    input  wire S_AXI_CALIPTRA_WLAST,
    // B
    output wire [1:0] S_AXI_CALIPTRA_BRESP,
    output wire [15:0] S_AXI_CALIPTRA_BID,
    output wire S_AXI_CALIPTRA_BVALID,
    input  wire S_AXI_CALIPTRA_BREADY,
    // AR
    input  wire [31:0] S_AXI_CALIPTRA_ARADDR,
    input  wire [1:0] S_AXI_CALIPTRA_ARBURST,
    input  wire [2:0] S_AXI_CALIPTRA_ARSIZE,
    input  wire [7:0] S_AXI_CALIPTRA_ARLEN,
    input  wire [31:0] S_AXI_CALIPTRA_ARUSER,
    input  wire [15:0] S_AXI_CALIPTRA_ARID,
    input  wire S_AXI_CALIPTRA_ARLOCK,
    input  wire S_AXI_CALIPTRA_ARVALID,
    output wire S_AXI_CALIPTRA_ARREADY,
    // R
    output wire [31:0] S_AXI_CALIPTRA_RDATA,
    output wire [1:0] S_AXI_CALIPTRA_RRESP,
    output wire [15:0] S_AXI_CALIPTRA_RID,
    output wire S_AXI_CALIPTRA_RLAST,
    output wire S_AXI_CALIPTRA_RVALID,
    input  wire S_AXI_CALIPTRA_RREADY,

    // Caliptra M_AXI Interface
    output  wire [31:0] M_AXI_CALIPTRA_AWADDR,
    output  wire [1:0] M_AXI_CALIPTRA_AWBURST,
    output  wire [2:0] M_AXI_CALIPTRA_AWSIZE,
    output  wire [7:0] M_AXI_CALIPTRA_AWLEN,
    output  wire [31:0] M_AXI_CALIPTRA_AWUSER,
    output  wire [15:0] M_AXI_CALIPTRA_AWID,
    output  wire M_AXI_CALIPTRA_AWLOCK,
    output  wire M_AXI_CALIPTRA_AWVALID,
    input wire M_AXI_CALIPTRA_AWREADY,
    // W
    output  wire [31:0] M_AXI_CALIPTRA_WDATA,
    output  wire [3:0] M_AXI_CALIPTRA_WSTRB,
    output  wire M_AXI_CALIPTRA_WVALID,
    input wire M_AXI_CALIPTRA_WREADY,
    output  wire M_AXI_CALIPTRA_WLAST,
    // B
    input wire [1:0] M_AXI_CALIPTRA_BRESP,
    input wire  [15:0] M_AXI_CALIPTRA_BID,
    input wire M_AXI_CALIPTRA_BVALID,
    output  wire M_AXI_CALIPTRA_BREADY,
    // AR
    output  wire [31:0] M_AXI_CALIPTRA_ARADDR,
    output  wire [1:0] M_AXI_CALIPTRA_ARBURST,
    output  wire [2:0] M_AXI_CALIPTRA_ARSIZE,
    output  wire [7:0] M_AXI_CALIPTRA_ARLEN,
    output  wire [31:0] M_AXI_CALIPTRA_ARUSER,
    output  wire [15:0] M_AXI_CALIPTRA_ARID,
    output  wire M_AXI_CALIPTRA_ARLOCK,
    output  wire M_AXI_CALIPTRA_ARVALID,
    input wire M_AXI_CALIPTRA_ARREADY,
    // R
    input wire [31:0] M_AXI_CALIPTRA_RDATA,
    input wire [1:0] M_AXI_CALIPTRA_RRESP,
    input wire [15:0] M_AXI_CALIPTRA_RID,
    input wire M_AXI_CALIPTRA_RLAST,
    input wire M_AXI_CALIPTRA_RVALID,
    output  wire M_AXI_CALIPTRA_RREADY,

    // ROM AXI Interface
    input  wire                       axi_bram_clk,
    input  wire                       axi_bram_en,
    input  wire [3:0]                 axi_bram_we,
    input  wire [16:0]                axi_bram_addr,
    input  wire [31:0]                axi_bram_din,
    output wire [31:0]                axi_bram_dout,
    input  wire                       axi_bram_rst,

    // JTAG Interface
    input wire [4:0]                  jtag_in,     // JTAG input signals concatenated
    output wire [4:0]                 jtag_out,    // JTAG tdo

    // FPGA Realtime register AXI Interface
    input	wire                      S_AXI_WRAPPER_ARESETN,
    input	wire                      S_AXI_WRAPPER_AWVALID,
    output	wire                      S_AXI_WRAPPER_AWREADY,
    input	wire [31:0]               S_AXI_WRAPPER_AWADDR,
    input	wire [2:0]                S_AXI_WRAPPER_AWPROT,
    input	wire                      S_AXI_WRAPPER_WVALID,
    output	wire                      S_AXI_WRAPPER_WREADY,
    input	wire [31:0]               S_AXI_WRAPPER_WDATA,
    input	wire [3:0]                S_AXI_WRAPPER_WSTRB,
    output	wire                      S_AXI_WRAPPER_BVALID,
    input	wire                      S_AXI_WRAPPER_BREADY,
    output	wire [1:0]                S_AXI_WRAPPER_BRESP,
    input	wire                      S_AXI_WRAPPER_ARVALID,
    output	wire                      S_AXI_WRAPPER_ARREADY,
    input	wire [31:0]               S_AXI_WRAPPER_ARADDR,
    input	wire [2:0]                S_AXI_WRAPPER_ARPROT,
    output	wire                      S_AXI_WRAPPER_RVALID,
    input	wire                      S_AXI_WRAPPER_RREADY,
    output	wire [31:0]               S_AXI_WRAPPER_RDATA,
    output	wire [1:0]                S_AXI_WRAPPER_RRESP
    );

caliptra_wrapper_top cptra_wrapper (
    .core_clk(core_clk),

    // Caliptra AXI Interface
    .S_AXI_CALIPTRA_AWADDR(S_AXI_CALIPTRA_AWADDR),
    .S_AXI_CALIPTRA_AWBURST(S_AXI_CALIPTRA_AWBURST),
    .S_AXI_CALIPTRA_AWSIZE(S_AXI_CALIPTRA_AWSIZE),
    .S_AXI_CALIPTRA_AWLEN(S_AXI_CALIPTRA_AWLEN),
    .S_AXI_CALIPTRA_AWUSER(S_AXI_CALIPTRA_AWUSER),
    .S_AXI_CALIPTRA_AWID(S_AXI_CALIPTRA_AWID),
    .S_AXI_CALIPTRA_AWLOCK(S_AXI_CALIPTRA_AWLOCK),
    .S_AXI_CALIPTRA_AWVALID(S_AXI_CALIPTRA_AWVALID),
    .S_AXI_CALIPTRA_AWREADY(S_AXI_CALIPTRA_AWREADY),
    .S_AXI_CALIPTRA_WDATA(S_AXI_CALIPTRA_WDATA),
    .S_AXI_CALIPTRA_WSTRB(S_AXI_CALIPTRA_WSTRB),
    .S_AXI_CALIPTRA_WVALID(S_AXI_CALIPTRA_WVALID),
    .S_AXI_CALIPTRA_WREADY(S_AXI_CALIPTRA_WREADY),
    .S_AXI_CALIPTRA_WLAST(S_AXI_CALIPTRA_WLAST),
    .S_AXI_CALIPTRA_BRESP(S_AXI_CALIPTRA_BRESP),
    .S_AXI_CALIPTRA_BID(S_AXI_CALIPTRA_BID),
    .S_AXI_CALIPTRA_BVALID(S_AXI_CALIPTRA_BVALID),
    .S_AXI_CALIPTRA_BREADY(S_AXI_CALIPTRA_BREADY),
    .S_AXI_CALIPTRA_ARADDR(S_AXI_CALIPTRA_ARADDR),
    .S_AXI_CALIPTRA_ARBURST(S_AXI_CALIPTRA_ARBURST),
    .S_AXI_CALIPTRA_ARSIZE(S_AXI_CALIPTRA_ARSIZE),
    .S_AXI_CALIPTRA_ARLEN(S_AXI_CALIPTRA_ARLEN),
    .S_AXI_CALIPTRA_ARUSER(S_AXI_CALIPTRA_ARUSER),
    .S_AXI_CALIPTRA_ARID(S_AXI_CALIPTRA_ARID),
    .S_AXI_CALIPTRA_ARLOCK(S_AXI_CALIPTRA_ARLOCK),
    .S_AXI_CALIPTRA_ARVALID(S_AXI_CALIPTRA_ARVALID),
    .S_AXI_CALIPTRA_ARREADY(S_AXI_CALIPTRA_ARREADY),
    .S_AXI_CALIPTRA_RDATA(S_AXI_CALIPTRA_RDATA),
    .S_AXI_CALIPTRA_RRESP(S_AXI_CALIPTRA_RRESP),
    .S_AXI_CALIPTRA_RID(S_AXI_CALIPTRA_RID),
    .S_AXI_CALIPTRA_RLAST(S_AXI_CALIPTRA_RLAST),
    .S_AXI_CALIPTRA_RVALID(S_AXI_CALIPTRA_RVALID),
    .S_AXI_CALIPTRA_RREADY(S_AXI_CALIPTRA_RREADY),

    // Caliptra M_AXI Interface
    .M_AXI_CALIPTRA_AWADDR(M_AXI_CALIPTRA_AWADDR),
    .M_AXI_CALIPTRA_AWBURST(M_AXI_CALIPTRA_AWBURST),
    .M_AXI_CALIPTRA_AWSIZE(M_AXI_CALIPTRA_AWSIZE),
    .M_AXI_CALIPTRA_AWLEN(M_AXI_CALIPTRA_AWLEN),
    .M_AXI_CALIPTRA_AWUSER(M_AXI_CALIPTRA_AWUSER),
    .M_AXI_CALIPTRA_AWID(M_AXI_CALIPTRA_AWID),
    .M_AXI_CALIPTRA_AWLOCK(M_AXI_CALIPTRA_AWLOCK),
    .M_AXI_CALIPTRA_AWVALID(M_AXI_CALIPTRA_AWVALID),
    .M_AXI_CALIPTRA_AWREADY(M_AXI_CALIPTRA_AWREADY),
    // W
    .M_AXI_CALIPTRA_WDATA(M_AXI_CALIPTRA_WDATA),
    .M_AXI_CALIPTRA_WSTRB(M_AXI_CALIPTRA_WSTRB),
    .M_AXI_CALIPTRA_WVALID(M_AXI_CALIPTRA_WVALID),
    .M_AXI_CALIPTRA_WREADY(M_AXI_CALIPTRA_WREADY),
    .M_AXI_CALIPTRA_WLAST(M_AXI_CALIPTRA_WLAST),
    // B
    .M_AXI_CALIPTRA_BRESP(M_AXI_CALIPTRA_BRESP),
    .M_AXI_CALIPTRA_BID(M_AXI_CALIPTRA_BID),
    .M_AXI_CALIPTRA_BVALID(M_AXI_CALIPTRA_BVALID),
    .M_AXI_CALIPTRA_BREADY(M_AXI_CALIPTRA_BREADY),
    // AR
    .M_AXI_CALIPTRA_ARADDR(M_AXI_CALIPTRA_ARADDR),
    .M_AXI_CALIPTRA_ARBURST(M_AXI_CALIPTRA_ARBURST),
    .M_AXI_CALIPTRA_ARSIZE(M_AXI_CALIPTRA_ARSIZE),
    .M_AXI_CALIPTRA_ARLEN(M_AXI_CALIPTRA_ARLEN),
    .M_AXI_CALIPTRA_ARUSER(M_AXI_CALIPTRA_ARUSER),
    .M_AXI_CALIPTRA_ARID(M_AXI_CALIPTRA_ARID),
    .M_AXI_CALIPTRA_ARLOCK(M_AXI_CALIPTRA_ARLOCK),
    .M_AXI_CALIPTRA_ARVALID(M_AXI_CALIPTRA_ARVALID),
    .M_AXI_CALIPTRA_ARREADY(M_AXI_CALIPTRA_ARREADY),
    // R
    .M_AXI_CALIPTRA_RDATA(M_AXI_CALIPTRA_RDATA),
    .M_AXI_CALIPTRA_RRESP(M_AXI_CALIPTRA_RRESP),
    .M_AXI_CALIPTRA_RID(M_AXI_CALIPTRA_RID),
    .M_AXI_CALIPTRA_RLAST(M_AXI_CALIPTRA_RLAST),
    .M_AXI_CALIPTRA_RVALID(M_AXI_CALIPTRA_RVALID),
    .M_AXI_CALIPTRA_RREADY(M_AXI_CALIPTRA_RREADY),

    // SOC access to program ROM
    .axi_bram_clk(axi_bram_clk),
    .axi_bram_en(axi_bram_en),
    .axi_bram_we(axi_bram_we),
    .axi_bram_addr(axi_bram_addr[16:2]),
    .axi_bram_wrdata(axi_bram_din),
    .axi_bram_rddata(axi_bram_dout),
    .axi_bram_rst(axi_bram_rst),

    // EL2 JTAG interface
    .jtag_tck(jtag_in[0]),
    .jtag_tdi(jtag_in[1]),
    .jtag_tms(jtag_in[2]),
    .jtag_trst_n(jtag_in[3]),
    .jtag_tdo(jtag_out[4]),

    // FPGA Realtime register AXI Interface
    .S_AXI_WRAPPER_ARESETN(S_AXI_WRAPPER_ARESETN),
    .S_AXI_WRAPPER_AWVALID(S_AXI_WRAPPER_AWVALID),
    .S_AXI_WRAPPER_AWREADY(S_AXI_WRAPPER_AWREADY),
    .S_AXI_WRAPPER_AWADDR(S_AXI_WRAPPER_AWADDR),
    .S_AXI_WRAPPER_AWPROT(S_AXI_WRAPPER_AWPROT),
    .S_AXI_WRAPPER_WVALID(S_AXI_WRAPPER_WVALID),
    .S_AXI_WRAPPER_WREADY(S_AXI_WRAPPER_WREADY),
    .S_AXI_WRAPPER_WDATA(S_AXI_WRAPPER_WDATA),
    .S_AXI_WRAPPER_WSTRB(S_AXI_WRAPPER_WSTRB),
    .S_AXI_WRAPPER_BVALID(S_AXI_WRAPPER_BVALID),
    .S_AXI_WRAPPER_BREADY(S_AXI_WRAPPER_BREADY),
    .S_AXI_WRAPPER_BRESP(S_AXI_WRAPPER_BRESP),
    .S_AXI_WRAPPER_ARVALID(S_AXI_WRAPPER_ARVALID),
    .S_AXI_WRAPPER_ARREADY(S_AXI_WRAPPER_ARREADY),
    .S_AXI_WRAPPER_ARADDR(S_AXI_WRAPPER_ARADDR),
    .S_AXI_WRAPPER_ARPROT(S_AXI_WRAPPER_ARPROT),
    .S_AXI_WRAPPER_RVALID(S_AXI_WRAPPER_RVALID),
    .S_AXI_WRAPPER_RREADY(S_AXI_WRAPPER_RREADY),
    .S_AXI_WRAPPER_RDATA(S_AXI_WRAPPER_RDATA),
    .S_AXI_WRAPPER_RRESP(S_AXI_WRAPPER_RRESP)
);

endmodule
