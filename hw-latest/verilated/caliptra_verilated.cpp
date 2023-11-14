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

  v->paddr = in->paddr;
  v->pprot = in->pprot;
  v->psel = in->psel;
  v->penable = in->penable;
  v->pwrite = in->pwrite;
  v->pwdata = in->pwdata;
  v->pauser = in->pauser;

  v->ext_imem_we = in->imem_we;
  v->ext_imem_addr = in->imem_addr;
  v->ext_imem_wdata = in->imem_wdata;

  v->ext_dccm_we = in->ext_dccm_we;
  v->ext_iccm_we = in->ext_iccm_we;
  v->ext_mbox_we = in->ext_mbox_we;
  v->ext_xccm_addr = in->ext_xccm_addr;
  v->ext_xccm_wdata[0] = in->ext_xccm_wdata[0];
  v->ext_xccm_wdata[1] = in->ext_xccm_wdata[1];
  v->ext_xccm_wdata[2] = in->ext_xccm_wdata[2];
  v->ext_xccm_wdata[3] = in->ext_xccm_wdata[3];
  v->ext_xccm_wdata[4] = in->ext_xccm_wdata[4];

  v->itrng_data = in->itrng_data;
  v->itrng_valid = in->itrng_valid;

  v->sram_error_injection_mode = in->sram_error_injection_mode;

  if (model->tfp.get()) {
    model->tfp->dump(model->sim_time++);
  }

  out->ready_for_fuses = v->ready_for_fuses;
  out->ready_for_fw_push = v->ready_for_fw_push;

  out->pready = v->pready;
  out->pslverr = v->pslverr;
  out->prdata = v->prdata;

  out->generic_output_wires = v->generic_output_wires;

  out->etrng_req = v->etrng_req;

  out->uc_haddr = v->uc_haddr;
  out->uc_hburst = v->uc_hburst;
  out->uc_hmastlock = v->uc_hmastlock;
  out->uc_hprot = v->uc_hprot;
  out->uc_hsize = v->uc_hsize;
  out->uc_htrans = v->uc_htrans;
  out->uc_hwrite = v->uc_hwrite;
  out->uc_hwdata = v->uc_hwdata;

  out->uc_hrdata = v->uc_hrdata;
  out->uc_hready = v->uc_hready;
  out->uc_hresp = v->uc_hresp;
}

