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

import caliptra_fpga_realtime_regs_pkg::*;

module caliptra_wrapper_top (
    input bit core_clk,

`ifdef CALIPTRA_APB
    // Caliptra APB Interface
    input  wire [`CALIPTRA_APB_ADDR_WIDTH-1:0] PADDR,
    input  wire                       PENABLE,
    input  wire [2:0]                 PPROT,
    output wire [`CALIPTRA_APB_DATA_WIDTH-1:0] PRDATA,
    output wire                       PREADY,
    input  wire                       PSEL,
    output wire                       PSLVERR,
    input  wire [`CALIPTRA_APB_DATA_WIDTH-1:0] PWDATA,
    input  wire                       PWRITE,
`else
    // Caliptra S_AXI Interface
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
    output reg  [15:0] S_AXI_CALIPTRA_BID,
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
    output reg  [15:0] S_AXI_CALIPTRA_RID,
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
    input reg  [15:0] M_AXI_CALIPTRA_BID,
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
    input reg  [15:0] M_AXI_CALIPTRA_RID,
    input wire M_AXI_CALIPTRA_RLAST,
    input wire M_AXI_CALIPTRA_RVALID,
    output  wire M_AXI_CALIPTRA_RREADY,
`endif

    // ROM AXI Interface
    input  logic axi_bram_clk,
    input  logic axi_bram_en,
    input  logic [3:0] axi_bram_we,
    input  logic [14:0] axi_bram_addr,
    input  logic [31:0] axi_bram_wrdata,
    output logic [31:0] axi_bram_rddata,
    input  logic axi_bram_rst,

    // JTAG Interface
    input logic                       jtag_tck,    // JTAG clk
    input logic                       jtag_tms,    // JTAG tms
    input logic                       jtag_tdi,    // JTAG tdi
    input logic                       jtag_trst_n, // JTAG reset
    output logic                      jtag_tdo,    // JTAG tdo

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

    import soc_ifc_pkg::*;

    logic                       BootFSM_BrkPoint;

    logic mbox_sram_cs;
    logic mbox_sram_we;
    logic [15:0] mbox_sram_addr;
    logic [39-1:0] mbox_sram_wdata; // TODO: What file can be brought in for defining CPTRA_MBOX_DATA_AND_ECC_W?
    logic [39-1:0] mbox_sram_rdata; // TODO: What file can be brought in for defining CPTRA_MBOX_DATA_AND_ECC_W?

    logic imem_cs;
    logic [`CALIPTRA_IMEM_ADDR_WIDTH-1:0] imem_addr;
    logic [`CALIPTRA_IMEM_DATA_WIDTH-1:0] imem_rdata;

    logic [255:0]                              cptra_obf_key;
    (* syn_keep = "true", mark_debug = "true" *) logic [`CLP_CSR_HMAC_KEY_DWORDS-1:0][31:0] cptra_csr_hmac_key;
    logic [`CLP_OBF_FE_DWORDS-1 :0][31:0]      cptra_obf_field_entropy;
    logic [`CLP_OBF_UDS_DWORDS-1:0][31:0]      cptra_obf_uds_seed;
    assign cptra_obf_key =
        {hwif_out.interface_regs.cptra_obf_key[7].value.value,
         hwif_out.interface_regs.cptra_obf_key[6].value.value,
         hwif_out.interface_regs.cptra_obf_key[5].value.value,
         hwif_out.interface_regs.cptra_obf_key[4].value.value,
         hwif_out.interface_regs.cptra_obf_key[3].value.value,
         hwif_out.interface_regs.cptra_obf_key[2].value.value,
         hwif_out.interface_regs.cptra_obf_key[1].value.value,
         hwif_out.interface_regs.cptra_obf_key[0].value.value};
    always_comb begin
      for (int dword = 0; dword < `CLP_CSR_HMAC_KEY_DWORDS; dword++) begin
         cptra_csr_hmac_key[dword] = hwif_out.interface_regs.cptra_csr_hmac_key[dword].value.value;
      end
    end
    always_comb begin
      for (int dword = 0; dword < `CLP_OBF_FE_DWORDS; dword++) begin
         cptra_obf_field_entropy[dword] = hwif_out.interface_regs.cptra_obf_field_entropy[dword].value.value;
      end
    end
    always_comb begin
      for (int dword = 0; dword < `CLP_OBF_UDS_DWORDS; dword++) begin
         cptra_obf_uds_seed[dword] = hwif_out.interface_regs.cptra_obf_uds_seed[dword].value.value;
      end
    end

`ifndef CALIPTRA_APB
    axi_if #(
        .AW(`CALIPTRA_SLAVE_ADDR_WIDTH(`CALIPTRA_SLAVE_SEL_SOC_IFC)),
        .DW(`CALIPTRA_AXI_DATA_WIDTH),
        .IW(`CALIPTRA_AXI_ID_WIDTH),
        .UW(`CALIPTRA_AXI_USER_WIDTH)
    ) s_axi (.clk(core_clk), .rst_n(hwif_out.interface_regs.control.cptra_rst_b.value));

    // AW
    assign s_axi.awaddr   = S_AXI_CALIPTRA_AWADDR;
    assign s_axi.awburst  = S_AXI_CALIPTRA_AWBURST;
    assign s_axi.awsize   = S_AXI_CALIPTRA_AWSIZE;
    assign s_axi.awlen    = S_AXI_CALIPTRA_AWLEN;
    assign s_axi.awuser   = hwif_out.interface_regs.pauser.pauser.value; //S_AXI_CALIPTRA_AWUSER;
    assign s_axi.awid     = S_AXI_CALIPTRA_AWID;
    assign s_axi.awlock   = S_AXI_CALIPTRA_AWLOCK;
    assign s_axi.awvalid  = S_AXI_CALIPTRA_AWVALID;
    assign S_AXI_CALIPTRA_AWREADY = s_axi.awready;
    // W
    assign s_axi.wdata    = S_AXI_CALIPTRA_WDATA;
    assign s_axi.wstrb    = S_AXI_CALIPTRA_WSTRB;
    assign s_axi.wvalid   = S_AXI_CALIPTRA_WVALID;
    assign S_AXI_CALIPTRA_WREADY = s_axi.wready;
    assign s_axi.wlast    = S_AXI_CALIPTRA_WLAST;
    // B
    assign S_AXI_CALIPTRA_BRESP  = s_axi.bresp;
    assign S_AXI_CALIPTRA_BID    = s_axi.bid;
    assign S_AXI_CALIPTRA_BVALID = s_axi.bvalid;
    assign s_axi.bready  = S_AXI_CALIPTRA_BREADY;
    // AR
    assign s_axi.araddr  = S_AXI_CALIPTRA_ARADDR;
    assign s_axi.arburst = S_AXI_CALIPTRA_ARBURST;
    assign s_axi.arsize  = S_AXI_CALIPTRA_ARSIZE;
    assign s_axi.arlen   = S_AXI_CALIPTRA_ARLEN;
    assign s_axi.aruser  = hwif_out.interface_regs.pauser.pauser.value; // S_AXI_CALIPTRA_ARUSER;
    assign s_axi.arid    = S_AXI_CALIPTRA_ARID;
    assign s_axi.arlock  = S_AXI_CALIPTRA_ARLOCK;
    assign s_axi.arvalid = S_AXI_CALIPTRA_ARVALID;
    assign S_AXI_CALIPTRA_ARREADY = s_axi.arready;
    // R
    assign S_AXI_CALIPTRA_RDATA  = s_axi.rdata;
    assign S_AXI_CALIPTRA_RRESP  = s_axi.rresp;
    assign S_AXI_CALIPTRA_RID    = s_axi.rid;
    assign S_AXI_CALIPTRA_RLAST  = s_axi.rlast;
    assign S_AXI_CALIPTRA_RVALID = s_axi.rvalid;
    assign s_axi.rready = S_AXI_CALIPTRA_RREADY;

    // Unused master interface
    axi_if #(
        .AW(`CALIPTRA_SLAVE_ADDR_WIDTH(`CALIPTRA_SLAVE_SEL_SOC_IFC)),
        .DW(`CALIPTRA_AXI_DATA_WIDTH),
        .IW(`CALIPTRA_AXI_ID_WIDTH),
        .UW(`CALIPTRA_AXI_USER_WIDTH)
    ) m_axi (.clk(core_clk), .rst_n(hwif_out.interface_regs.control.cptra_rst_b.value));

    // AW
    assign M_AXI_CALIPTRA_AWADDR =  m_axi.awaddr;
    assign M_AXI_CALIPTRA_AWBURST = m_axi.awburst;
    assign M_AXI_CALIPTRA_AWSIZE =  m_axi.awsize;
    assign M_AXI_CALIPTRA_AWLEN =   m_axi.awlen;
    assign M_AXI_CALIPTRA_AWUSER =  m_axi.awuser;
    assign M_AXI_CALIPTRA_AWID = m_axi.awid;
    assign M_AXI_CALIPTRA_AWLOCK = m_axi.awlock;
    assign M_AXI_CALIPTRA_AWVALID = m_axi.awvalid;
    assign m_axi.awready = M_AXI_CALIPTRA_AWREADY;
    // W
    assign M_AXI_CALIPTRA_WDATA =   m_axi.wdata;
    assign M_AXI_CALIPTRA_WSTRB =   m_axi.wstrb;
    assign M_AXI_CALIPTRA_WVALID =  m_axi.wvalid;
    assign m_axi.wready = M_AXI_CALIPTRA_WREADY;
    assign M_AXI_CALIPTRA_WLAST =   m_axi.wlast;
    // B
    assign m_axi.bresp =    M_AXI_CALIPTRA_BRESP;
    assign m_axi.bid =      M_AXI_CALIPTRA_BID;
    assign m_axi.bvalid =   M_AXI_CALIPTRA_BVALID;
    assign M_AXI_CALIPTRA_BREADY = m_axi.bready;
    // AR
    assign M_AXI_CALIPTRA_ARADDR = m_axi.araddr;
    assign M_AXI_CALIPTRA_ARBURST = m_axi.arburst;
    assign M_AXI_CALIPTRA_ARSIZE = m_axi.arsize;
    assign M_AXI_CALIPTRA_ARLEN = m_axi.arlen;
    assign M_AXI_CALIPTRA_ARUSER = m_axi.aruser;
    assign M_AXI_CALIPTRA_ARID = m_axi.arid;
    assign M_AXI_CALIPTRA_ARLOCK = m_axi.arlock;
    assign M_AXI_CALIPTRA_ARVALID = m_axi.arvalid;
    assign m_axi.arready = M_AXI_CALIPTRA_ARREADY;
    // R
    assign m_axi.rdata =    M_AXI_CALIPTRA_RDATA;
    assign m_axi.rresp =    M_AXI_CALIPTRA_RRESP;
    assign m_axi.rid =      M_AXI_CALIPTRA_RID;
    assign m_axi.rlast =    M_AXI_CALIPTRA_RLAST;
    assign m_axi.rvalid =   M_AXI_CALIPTRA_RVALID;
    assign M_AXI_CALIPTRA_RREADY = m_axi.rready;


`endif
    el2_mem_if el2_mem_export();
    mldsa_mem_if mldsa_memory_export();

    initial begin
        BootFSM_BrkPoint = 1'b1; //Set to 1 even before anything starts
    end

    // TRNG Interface
    logic etrng_req;
    logic [3:0] itrng_data;
    logic itrng_valid;

    mldsa_mem_top mldsa_mem_top_inst (
        .clk_i(core_clk),
        .mldsa_memory_export(mldsa_memory_export.resp)
);

//=========================================================================-
// DUT instance
//=========================================================================-
caliptra_top caliptra_top_dut (
    .cptra_pwrgood              (hwif_out.interface_regs.control.cptra_pwrgood.value),
    .cptra_rst_b                (hwif_out.interface_regs.control.cptra_rst_b.value),
    .clk                        (core_clk),

    .cptra_obf_key,
    .cptra_csr_hmac_key,
    .cptra_obf_field_entropy_vld(hwif_out.interface_regs.control.cptra_obf_field_entropy_vld.value),
    .cptra_obf_field_entropy,
    .cptra_obf_uds_seed_vld(hwif_out.interface_regs.control.cptra_obf_uds_seed_vld.value),
    .cptra_obf_uds_seed,

    .jtag_tck(jtag_tck),
    .jtag_tdi(jtag_tdi),
    .jtag_tms(jtag_tms),
    .jtag_trst_n(jtag_trst_n),
    .jtag_tdo(jtag_tdo),
    // jtag_tdoEn

`ifdef CALIPTRA_APB
    // SoC APB Interface
    .PADDR(PADDR),
    .PPROT(PPROT),
    .PAUSER(hwif_out.interface_regs.pauser.pauser.value),
    .PENABLE(PENABLE),
    .PRDATA(PRDATA),
    .PREADY(PREADY),
    .PSEL(PSEL),
    .PSLVERR(PSLVERR),
    .PWDATA(PWDATA),
    .PWRITE(PWRITE),
`else
    // Subordinate AXI Interface
    .s_axi_w_if(s_axi.w_sub),
    .s_axi_r_if(s_axi.r_sub),

    // Manager AXI Interface
    .m_axi_w_if(m_axi.w_mgr),
    .m_axi_r_if(m_axi.r_mgr),

    // TODO: New addition
    .recovery_data_avail(0),
`endif

    .el2_mem_export(el2_mem_export.veer_sram_src),
    .mldsa_memory_export(mldsa_memory_export.req),

    .ready_for_fuses(hwif_in.interface_regs.status.ready_for_fuses.next),
    .ready_for_mb_processing(hwif_in.interface_regs.status.ready_for_mb_processing.next),
    .ready_for_runtime(hwif_in.interface_regs.status.ready_for_runtime.next),

    .mbox_sram_cs(mbox_sram_cs),
    .mbox_sram_we(mbox_sram_we),
    .mbox_sram_addr(mbox_sram_addr),
    .mbox_sram_wdata(mbox_sram_wdata),
    .mbox_sram_rdata(mbox_sram_rdata),

    .imem_cs(imem_cs),
    .imem_addr(imem_addr),
    .imem_rdata(imem_rdata),

    .mailbox_data_avail(hwif_in.interface_regs.status.mailbox_data_avail.next),
    .mailbox_flow_done(hwif_in.interface_regs.status.mailbox_flow_done.next),

    .BootFSM_BrkPoint(BootFSM_BrkPoint),

    //SoC Interrupts
    .cptra_error_fatal    (hwif_in.interface_regs.status.cptra_error_fatal.next),
    .cptra_error_non_fatal(hwif_in.interface_regs.status.cptra_error_non_fatal.next),

    .etrng_req             (etrng_req),
    .itrng_data            (itrng_data),
    .itrng_valid           (itrng_valid),

    .generic_input_wires({hwif_out.interface_regs.generic_input_wires[1].value.value, hwif_out.interface_regs.generic_input_wires[0].value.value}),
    .generic_output_wires({hwif_in.interface_regs.generic_output_wires[1].value.next, hwif_in.interface_regs.generic_output_wires[0].value.next}),

    .security_state({hwif_out.interface_regs.control.ss_debug_locked.value, hwif_out.interface_regs.control.ss_device_lifecycle.value}),
    .scan_mode     (hwif_out.interface_regs.control.scan_mode.value),
    .ss_debug_intent(hwif_out.interface_regs.control.ss_debug_intent.value)
);


// EL2 Memory
caliptra_veer_sram_export veer_sram_export_inst (
    .el2_mem_export(el2_mem_export.veer_sram_sink)
);

// Mailbox RAM
   xpm_memory_spram #(
      .ADDR_WIDTH_A(16),             // DECIMAL
      .AUTO_SLEEP_TIME(0),           // DECIMAL
      .BYTE_WRITE_WIDTH_A(39),       // DECIMAL
      .CASCADE_HEIGHT(0),            // DECIMAL
      .ECC_MODE("no_ecc"),           // String
      .MEMORY_INIT_FILE("none"),     // String
      .MEMORY_INIT_PARAM("0"),       // String
      .MEMORY_OPTIMIZATION("true"),  // String
      .MEMORY_PRIMITIVE("auto"),     // String
      .MEMORY_SIZE(256*1024*8*39/32), // DECIMAL
      .MESSAGE_CONTROL(0),           // DECIMAL
      .READ_DATA_WIDTH_A(39),        // DECIMAL
      .READ_LATENCY_A(1),            // DECIMAL
      .READ_RESET_VALUE_A("0"),      // String
      .RST_MODE_A("SYNC"),           // String
      .SIM_ASSERT_CHK(0),            // DECIMAL; 0=disable simulation messages, 1=enable simulation messages
      .USE_MEM_INIT(1),              // DECIMAL
      .USE_MEM_INIT_MMI(0),          // DECIMAL
      .WAKEUP_TIME("disable_sleep"), // String
      .WRITE_DATA_WIDTH_A(39),       // DECIMAL
      .WRITE_MODE_A("read_first"),   // String
      .WRITE_PROTECT(1)              // DECIMAL
   )
   mbox_ram1 (
      .dbiterra(),
      .douta(mbox_sram_rdata),
      .sbiterra(),
      .addra(mbox_sram_addr),
      .clka(core_clk),
      .dina(mbox_sram_wdata),
      .ena(mbox_sram_cs),
      .injectdbiterra(0),
      .injectsbiterra(0),
      .regcea(1'b1),
      .rsta(axi_bram_rst),
      .sleep(0),
      .wea(mbox_sram_we)

   );

// SRAM for imem/ROM
   xpm_memory_tdpram #(
      .ADDR_WIDTH_A(`CALIPTRA_IMEM_ADDR_WIDTH), // DECIMAL
      .ADDR_WIDTH_B(15),              // DECIMAL
      .AUTO_SLEEP_TIME(0),            // DECIMAL
      .BYTE_WRITE_WIDTH_A(64),        // DECIMAL
      .BYTE_WRITE_WIDTH_B(8),         // DECIMAL
      .CASCADE_HEIGHT(0),             // DECIMAL
      .CLOCKING_MODE("common_clock"), // String
      .ECC_MODE("no_ecc"),            // String
      .MEMORY_INIT_FILE("none"),      // String
      .MEMORY_INIT_PARAM("0"),        // String
      .MEMORY_OPTIMIZATION("false"),  // String
      .MEMORY_PRIMITIVE("auto"),      // String
      .MEMORY_SIZE(96*1024*8),        // DECIMAL
      .MESSAGE_CONTROL(0),            // DECIMAL
      .READ_DATA_WIDTH_A(64),         // DECIMAL
      .READ_DATA_WIDTH_B(32),         // DECIMAL
      .READ_LATENCY_A(1),             // DECIMAL
      .READ_LATENCY_B(1),             // DECIMAL
      .READ_RESET_VALUE_A("0"),       // String
      .READ_RESET_VALUE_B("0"),       // String
      .RST_MODE_A("SYNC"),            // String
      .RST_MODE_B("SYNC"),            // String
      .SIM_ASSERT_CHK(0),             // DECIMAL; 0=disable simulation messages, 1=enable simulation messages
      .USE_EMBEDDED_CONSTRAINT(0),    // DECIMAL
      .USE_MEM_INIT(1),               // DECIMAL
      .USE_MEM_INIT_MMI(0),           // DECIMAL
      .WAKEUP_TIME("disable_sleep"),  // String
      .WRITE_DATA_WIDTH_A(64),        // DECIMAL
      .WRITE_DATA_WIDTH_B(32),        // DECIMAL
      .WRITE_MODE_A("no_change"),     // String
      .WRITE_MODE_B("no_change"),     // String
      .WRITE_PROTECT(1)               // DECIMAL
   )
   imem_inst1 (
      .dbiterra(),
      .dbiterrb(),
      .douta(imem_rdata),
      .doutb(axi_bram_rddata),
      .sbiterra(),
      .sbiterrb(),
      .addra(imem_addr),
      .addrb(axi_bram_addr),
      .clka(core_clk),
      .clkb(core_clk),
      .dina(0),
      .dinb(axi_bram_wrdata),
      .ena(imem_cs),
      .enb(axi_bram_en),
      .injectdbiterra(0),
      .injectdbiterrb(0),
      .injectsbiterra(0),
      .injectsbiterrb(0),
      .regcea(1),
      .regceb(1),
      .rsta(axi_bram_rst),
      .rstb(axi_bram_rst),
      .sleep(0),
      .wea(8'h0),
      .web(axi_bram_we)
   );

    axi4lite_intf s_axil ();

    caliptra_fpga_realtime_regs__in_t hwif_in;
    caliptra_fpga_realtime_regs__out_t hwif_out;

    assign S_AXI_WRAPPER_AWREADY = s_axil.AWREADY;
    assign S_AXI_WRAPPER_WREADY = s_axil.WREADY;
    assign S_AXI_WRAPPER_BVALID = s_axil.BVALID;
    assign S_AXI_WRAPPER_BRESP = s_axil.BRESP;
    assign S_AXI_WRAPPER_ARREADY = s_axil.ARREADY;
    assign S_AXI_WRAPPER_RVALID = s_axil.RVALID;
    assign S_AXI_WRAPPER_RDATA = s_axil.RDATA;
    assign S_AXI_WRAPPER_RRESP = s_axil.RRESP;

    always_comb begin
        s_axil.AWVALID = S_AXI_WRAPPER_AWVALID;
        s_axil.AWADDR =  S_AXI_WRAPPER_AWADDR;
        s_axil.AWPROT =  S_AXI_WRAPPER_AWPROT;

        s_axil.WVALID =  S_AXI_WRAPPER_WVALID;
        s_axil.WDATA =   S_AXI_WRAPPER_WDATA;
        s_axil.WSTRB =   S_AXI_WRAPPER_WSTRB;

        s_axil.BREADY =  S_AXI_WRAPPER_BREADY;

        s_axil.ARVALID = S_AXI_WRAPPER_ARVALID;
        s_axil.ARADDR =  S_AXI_WRAPPER_ARADDR;
        s_axil.ARPROT =  S_AXI_WRAPPER_ARPROT;

        s_axil.RREADY =  S_AXI_WRAPPER_RREADY;
    end

    // Register Block
    caliptra_fpga_realtime_regs regs (
        .clk(core_clk),
        .rst(~S_AXI_WRAPPER_ARESETN),

        .s_axil(s_axil),

        .hwif_in (hwif_in),
        .hwif_out(hwif_out)
    );

    // Valid = !Empty
    logic log_fifo_empty;
    assign hwif_in.fifo_regs.log_fifo_data.char_valid.next = ~log_fifo_empty;
    assign hwif_in.fifo_regs.log_fifo_status.log_fifo_empty.next = log_fifo_empty;

    // When rd_swacc is asserted, use the value of "valid" from when it was sampled.
    reg log_fifo_valid_f;
    always@(posedge core_clk) begin
        log_fifo_valid_f <= ~log_fifo_empty;
    end

    // Hierarchical references to generic output wires register. Use as input to log FIFO.
    logic fifo_write_en;
    logic [7:0] fifo_char;
    assign fifo_write_en = caliptra_top_dut.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.load_next;
    assign fifo_char[7:0] = caliptra_top_dut.soc_ifc_top1.i_soc_ifc_reg.field_combo.CPTRA_GENERIC_OUTPUT_WIRES[0].generic_wires.next[7:0];

   xpm_fifo_sync #(
      .CASCADE_HEIGHT(0),         // DECIMAL
      .DOUT_RESET_VALUE("0"),     // String
      .ECC_MODE("no_ecc"),        // String
      .FIFO_MEMORY_TYPE("block"), // String
      .FIFO_READ_LATENCY(0),      // DECIMAL
      .FIFO_WRITE_DEPTH(64*1024), // DECIMAL
      .FULL_RESET_VALUE(0),       // DECIMAL
      .PROG_EMPTY_THRESH(10),     // DECIMAL
      .PROG_FULL_THRESH(7168),    // DECIMAL Currently unused
      .RD_DATA_COUNT_WIDTH(16),   // DECIMAL
      .READ_DATA_WIDTH(8),        // DECIMAL
      .READ_MODE("fwft"),         // String
      .SIM_ASSERT_CHK(0),         // DECIMAL; 0=disable simulation messages, 1=enable simulation messages
      .USE_ADV_FEATURES("0000"),  // String
      .WAKEUP_TIME(0),            // DECIMAL
      .WRITE_DATA_WIDTH(8),       // DECIMAL
      .WR_DATA_COUNT_WIDTH(16)    // DECIMAL
   )
   log_fifo_inst (
      .almost_empty(),
      .almost_full(),
      .data_valid(),
      .dbiterr(),
      .dout(hwif_in.fifo_regs.log_fifo_data.next_char.next),
      .empty(log_fifo_empty),
      .full(hwif_in.fifo_regs.log_fifo_status.log_fifo_full.next),
      .overflow(),
      .prog_empty(),
      .prog_full(),
      .rd_data_count(),
      .rd_rst_busy(),
      .sbiterr(),
      .underflow(),
      .wr_ack(),
      .wr_data_count(),
      .wr_rst_busy(),
      .din(fifo_char),
      .injectdbiterr(0),
      .injectsbiterr(0),
      .rd_en(log_fifo_valid_f & hwif_out.fifo_regs.log_fifo_data.next_char.rd_swacc),
      .rst(~S_AXI_WRAPPER_ARESETN),
      .sleep(0),
      .wr_clk(core_clk),
      .wr_en(fifo_write_en)
   );


`ifdef CALIPTRA_INTERNAL_TRNG

    reg throttled_etrng_req;
    // wr_swacc is asserted one cycle before the hwif_out has the new value. Delay wr_en by one cycle.
    reg trng_fifo_wr_en;
    always@(posedge core_clk) begin
        trng_fifo_wr_en <= hwif_out.fifo_regs.itrng_fifo_data.itrng_data.wr_swacc;
    end

   xpm_fifo_sync #(
      .CASCADE_HEIGHT(0),         // DECIMAL
      .DOUT_RESET_VALUE("0"),     // String
      .ECC_MODE("no_ecc"),        // String
      .FIFO_MEMORY_TYPE("block"), // String
      .FIFO_READ_LATENCY(1),      // DECIMAL
      .FIFO_WRITE_DEPTH(1024),    // DECIMAL
      .FULL_RESET_VALUE(0),       // DECIMAL
      .PROG_EMPTY_THRESH(10),     // DECIMAL
      .PROG_FULL_THRESH(10),      // DECIMAL
      .RD_DATA_COUNT_WIDTH(13),   // DECIMAL
      .READ_DATA_WIDTH(4),        // DECIMAL
      .READ_MODE("std"),          // String
      .SIM_ASSERT_CHK(0),         // DECIMAL; 0=disable simulation messages, 1=enable simulation messages
      .USE_ADV_FEATURES("1000"),  // String
      .WAKEUP_TIME(0),            // DECIMAL
      .WRITE_DATA_WIDTH(32),      // DECIMAL
      .WR_DATA_COUNT_WIDTH(11)    // DECIMAL
   )
   trng_fifo_inst (
      .almost_empty(),
      .almost_full(),
      .data_valid(itrng_valid),
      .dbiterr(),
      .dout(itrng_data),
      .empty(hwif_in.fifo_regs.itrng_fifo_status.itrng_fifo_empty.next),
      .full(hwif_in.fifo_regs.itrng_fifo_status.itrng_fifo_full.next),
      .overflow(),
      .prog_empty(),
      .prog_full(),
      .rd_data_count(),
      .rd_rst_busy(),
      .sbiterr(),
      .underflow(),
      .wr_ack(),
      .wr_data_count(),
      .wr_rst_busy(),
      .din(hwif_out.fifo_regs.itrng_fifo_data.itrng_data.value),
      .injectdbiterr(0),
      .injectsbiterr(0),
      .rd_en(throttled_etrng_req),
      .rst(hwif_out.fifo_regs.itrng_fifo_status.itrng_fifo_reset.value),
      .sleep(0),
      .wr_clk(core_clk),
      .wr_en(trng_fifo_wr_en)
   );

    // Throttle etrng_req.
    reg [31:0] counter;
    always@(posedge core_clk) begin
        if (counter == 0) begin
            throttled_etrng_req <= etrng_req;
            counter <= hwif_out.interface_regs.itrng_divisor.itrng_divisor.value;
        end else begin
            throttled_etrng_req <= 0;
            counter <= counter - 1;
        end
    end
`else
    assign itrng_data  = 4'b0;
    assign itrng_valid = 1'b0;
`endif

    reg [31:0] cycle_count;
    always@(posedge core_clk or negedge hwif_out.interface_regs.control.cptra_rst_b.value) begin
        if (~hwif_out.interface_regs.control.cptra_rst_b.value) begin
            cycle_count <= 0;
        end
        else begin
            cycle_count <= cycle_count + 1;
        end
    end
    assign hwif_in.interface_regs.cycle_count.cycle_count.next = cycle_count;


    assign hwif_in.interface_regs.fpga_version.fpga_version.next = `FPGA_VERSION;
endmodule
