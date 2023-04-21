/*++
Licensed under the Apache-2.0 license.
--*/
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct caliptra_verilated;

struct caliptra_verilated_sig_in {
  bool core_clk;
  bool cptra_pwrgood;
  bool cptra_rst_b;

  uint32_t paddr;
  uint8_t pprot;
  bool psel;
  bool penable;
  bool pwrite;
  uint32_t pwdata;
  uint32_t pauser;

  bool imem_we;
  uint32_t imem_addr;
  uint64_t imem_wdata;

  uint8_t itrng_data;
  bool itrng_valid;
};

struct caliptra_verilated_sig_out {
  bool ready_for_fuses;
  bool ready_for_fw_push;

  bool pready;
  bool pslverr;
  uint32_t prdata;

  bool generic_load_en;
  uint32_t generic_load_data;

  bool etrng_req;
};

struct caliptra_verilated_init_args {
  uint32_t security_state;
};

// Constructs a new model. Model must eventually be destroyed with
// caliptra_verilated_destroy.
struct caliptra_verilated* caliptra_verilated_new(
    struct caliptra_verilated_init_args* args);

// Destroys the model.
void caliptra_verilated_destroy(struct caliptra_verilated* model);

// If `vcd_out_path` is not-null, the model will start tracing all signals less
// than `depth` to a VCD file at `vcd_out_path`. If vcd_out_path is null, the
// model will stop any tracing previously started.
//
// This function does not take ownership of vcd_out_path; the caller may reuse
// the buffer once this function has returned.
void caliptra_verilated_trace(struct caliptra_verilated* model,
                              const char* vcd_out_path, int depth);

// Evaluates the model into out, then copies all `in` signals into psuedo
// flip-flops that will be visible to always_ff blocks in subsequent
// evaluations.
void caliptra_verilated_eval(struct caliptra_verilated* model,
                             const struct caliptra_verilated_sig_in* in,
                             struct caliptra_verilated_sig_out* out);

#ifdef __cplusplus
}
#endif
