/*++
Licensed under the Apache-2.0 license.
--*/

// This file corresponds to the structs defined in caliptra_verilated.h

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_verilated {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct caliptra_verilated_sig_in {
    pub core_clk: bool,
    pub cptra_pwrgood: bool,
    pub cptra_rst_b: bool,

    // AXI Write Address Channel
    pub s_axi_awid: u8,
    pub s_axi_awaddr: u32,
    pub s_axi_awburst: u8,
    pub s_axi_awsize: u8,
    pub s_axi_awlen: u8,
    pub s_axi_awuser: u32,
    pub s_axi_awvalid: bool,
    pub s_axi_awlock: bool,

    // AXI Write Data Channel
    pub s_axi_wdata: u32,
    pub s_axi_wstrb: u8,
    pub s_axi_wvalid: bool,
    pub s_axi_wlast: bool,

    // AXI Write Response Channel
    pub s_axi_bready: bool,

    // AXI Read Address Channel
    pub s_axi_arid: u8,
    pub s_axi_araddr: u32,
    pub s_axi_arburst: u8,
    pub s_axi_arsize: u8,
    pub s_axi_arlen: u8,
    pub s_axi_aruser: u32,
    pub s_axi_arvalid: bool,
    pub s_axi_arlock: bool,

    // AXI Read Data Channel
    pub s_axi_rready: bool,

    // ROM backdoor write
    pub imem_we: bool,
    pub imem_addr: u32,
    pub imem_wdata: u64,

    // TRNG
    pub itrng_data: u8,
    pub itrng_valid: bool,

    pub sram_error_injection_mode: u8,

    // SRAM backdoor writes
    pub ext_iccm_we: bool,
    pub ext_dccm_we: bool,
    pub ext_mbox_we: bool,
    pub ext_xccm_addr: u32,
    pub ext_xccm_wdata: [u32; 5usize],
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct caliptra_verilated_sig_out {
    pub ready_for_fuses: bool,
    pub ready_for_mb_processing: bool,

    // AXI Write Address Channel
    pub s_axi_awready: bool,

    // AXI Write Data Channel
    pub s_axi_wready: bool,

    // AXI Write Response Channel
    pub s_axi_bid: u8,
    pub s_axi_bresp: u8,
    pub s_axi_bvalid: bool,

    // AXI Read Address Channel
    pub s_axi_arready: bool,

    // AXI Read Data Channel
    pub s_axi_rid: u8,
    pub s_axi_rdata: u32,
    pub s_axi_rresp: u8,
    pub s_axi_rlast: bool,
    pub s_axi_rvalid: bool,

    pub generic_output_wires: u64,
    pub etrng_req: bool,
    pub cptra_error_fatal: bool,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct caliptra_verilated_init_args {
    pub security_state: u32,
    pub cptra_obf_key: [u32; 8usize],
    pub cptra_csr_hmac_key: [u32; 16usize],
}
extern "C" {
    pub fn caliptra_verilated_new(
        args: *mut caliptra_verilated_init_args,
    ) -> *mut caliptra_verilated;
}
extern "C" {
    pub fn caliptra_verilated_destroy(model: *mut caliptra_verilated);
}
extern "C" {
    pub fn caliptra_verilated_trace(
        model: *mut caliptra_verilated,
        vcd_out_path: *const ::std::os::raw::c_char,
        depth: ::std::os::raw::c_int,
    );
}
extern "C" {
    pub fn caliptra_verilated_eval(
        model: *mut caliptra_verilated,
        in_: *const caliptra_verilated_sig_in,
        out: *mut caliptra_verilated_sig_out,
    );
}
