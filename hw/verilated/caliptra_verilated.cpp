/*++
Licensed under the Apache-2.0 license.
--*/
#include "caliptra_verilated.h"

#include "Vcaliptra_verilated.h"
#include "verilated_vcd_c.h"

struct caliptra_verilated {
  Vcaliptra_verilated v;
  std::unique_ptr<VerilatedVcdC> tfp;
  uint64_t sim_time = 0;
};

struct caliptra_verilated* caliptra_verilated_new(struct caliptra_verilated_init_args* init_args) {
  auto result = new caliptra_verilated();
  result->v.security_state = init_args->security_state;
  memcpy(result->v.cptra_obf_key, init_args->cptra_obf_key, sizeof(result->v.cptra_obf_key));
  memcpy(result->v.cptra_csr_hmac_key, init_args->cptra_csr_hmac_key, sizeof(result->v.cptra_csr_hmac_key));
  return result;
}
void caliptra_verilated_destroy(struct caliptra_verilated* model) {
  if (model->tfp.get()) {
    model->tfp->close();
  }
  delete model;
}

void caliptra_verilated_trace(struct caliptra_verilated* model,
                              const char* vcd_out_path, int depth) {
  Verilated::traceEverOn(vcd_out_path ? true : false);
  if (model->tfp.get()) {
    model->tfp->close();
  }
  model->tfp.reset(NULL);

  if (vcd_out_path) {
    model->tfp.reset(new VerilatedVcdC());

    model->v.trace(model->tfp.get(), depth);
    model->tfp->open(vcd_out_path);
  }
}

void caliptra_verilated_eval(struct caliptra_verilated* model,
                             const struct caliptra_verilated_sig_in* in,
                             struct caliptra_verilated_sig_out* out) {
  Vcaliptra_verilated* v = &model->v;

  v->eval();

  v->core_clk = in->core_clk;

  v->cptra_pwrgood = in->cptra_pwrgood;
  v->cptra_rst_b = in->cptra_rst_b;

  // AXI Write Address Channel
  v->s_axi_awid = in->s_axi_awid;
  v->s_axi_awaddr = in->s_axi_awaddr;
  v->s_axi_awburst = in->s_axi_awburst;
  v->s_axi_awsize = in->s_axi_awsize;
  v->s_axi_awlen = in->s_axi_awlen;
  v->s_axi_awuser = in->s_axi_awuser;
  v->s_axi_awvalid = in->s_axi_awvalid;
  v->s_axi_awlock = in->s_axi_awlock;

  // AXI Write Data Channel
  v->s_axi_wdata = in->s_axi_wdata;
  v->s_axi_wstrb = in->s_axi_wstrb;
  v->s_axi_wvalid = in->s_axi_wvalid;
  v->s_axi_wlast = in->s_axi_wlast;

  // AXI Write Response Channel
  v->s_axi_bready = in->s_axi_bready;

  // AXI Read Address Channel
  v->s_axi_arid = in->s_axi_arid;
  v->s_axi_araddr = in->s_axi_araddr;
  v->s_axi_arburst = in->s_axi_arburst;
  v->s_axi_arsize = in->s_axi_arsize;
  v->s_axi_arlen = in->s_axi_arlen;
  v->s_axi_aruser = in->s_axi_aruser;
  v->s_axi_arvalid = in->s_axi_arvalid;
  v->s_axi_arlock = in->s_axi_arlock;

  // AXI Read Data Channel
  v->s_axi_rready = in->s_axi_rready;

  // ROM backdoor write
  v->ext_imem_we = in->imem_we;
  v->ext_imem_addr = in->imem_addr;
  v->ext_imem_wdata = in->imem_wdata;

  // SRAM backdoor writes
  v->ext_dccm_we = in->ext_dccm_we;
  v->ext_iccm_we = in->ext_iccm_we;
  v->ext_mbox_we = in->ext_mbox_we;
  v->ext_xccm_addr = in->ext_xccm_addr;
  v->ext_xccm_wdata[0] = in->ext_xccm_wdata[0];
  v->ext_xccm_wdata[1] = in->ext_xccm_wdata[1];
  v->ext_xccm_wdata[2] = in->ext_xccm_wdata[2];
  v->ext_xccm_wdata[3] = in->ext_xccm_wdata[3];
  v->ext_xccm_wdata[4] = in->ext_xccm_wdata[4];

  // TRNG
  v->itrng_data = in->itrng_data;
  v->itrng_valid = in->itrng_valid;

  v->sram_error_injection_mode = in->sram_error_injection_mode;

  if (model->tfp.get()) {
    model->tfp->dump(model->sim_time++);
  }

  // Status outputs
  out->ready_for_fuses = v->ready_for_fuses;
  out->ready_for_mb_processing = v->ready_for_mb_processing;

  // AXI Write Address Channel
  out->s_axi_awready = v->s_axi_awready;

  // AXI Write Data Channel
  out->s_axi_wready = v->s_axi_wready;

  // AXI Write Response Channel
  out->s_axi_bid = v->s_axi_bid;
  out->s_axi_bresp = v->s_axi_bresp;
  out->s_axi_bvalid = v->s_axi_bvalid;

  // AXI Read Address Channel
  out->s_axi_arready = v->s_axi_arready;

  // AXI Read Data Channel
  out->s_axi_rid = v->s_axi_rid;
  out->s_axi_rdata = v->s_axi_rdata;
  out->s_axi_rresp = v->s_axi_rresp;
  out->s_axi_rlast = v->s_axi_rlast;
  out->s_axi_rvalid = v->s_axi_rvalid;

  out->generic_output_wires = v->generic_output_wires;

  out->etrng_req = v->etrng_req;

  out->cptra_error_fatal = v->cptra_error_fatal;
}
