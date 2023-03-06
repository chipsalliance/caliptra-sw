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

struct caliptra_verilated* caliptra_verilated_new(void) {
  return new caliptra_verilated();
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

  if (model->tfp.get()) {
    model->tfp->dump(model->sim_time++);
  }

  out->ready_for_fuses = v->ready_for_fuses;
  out->ready_for_fw_push = v->ready_for_fw_push;

  out->pready = v->pready;
  out->pslverr = v->pslverr;
  out->prdata = v->prdata;

  out->generic_load_en = v->generic_load_en;
  out->generic_load_data = v->generic_load_data;
}