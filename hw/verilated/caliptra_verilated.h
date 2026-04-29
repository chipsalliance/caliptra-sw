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

  // AXI Write Address Channel
  uint8_t s_axi_awid;
  uint32_t s_axi_awaddr;
  uint8_t s_axi_awburst;
  uint8_t s_axi_awsize;
  uint8_t s_axi_awlen;
  uint32_t s_axi_awuser;
  bool s_axi_awvalid;
  bool s_axi_awlock;

  // AXI Write Data Channel
  uint32_t s_axi_wdata;
  uint8_t s_axi_wstrb;
  bool s_axi_wvalid;
  bool s_axi_wlast;

  // AXI Write Response Channel
  bool s_axi_bready;

  // AXI Read Address Channel
  uint8_t s_axi_arid;
  uint32_t s_axi_araddr;
  uint8_t s_axi_arburst;
  uint8_t s_axi_arsize;
  uint8_t s_axi_arlen;
  uint32_t s_axi_aruser;
  bool s_axi_arvalid;
  bool s_axi_arlock;

  // AXI Read Data Channel
  bool s_axi_rready;

  // ROM backdoor write
  bool imem_we;
  uint32_t imem_addr;
  uint64_t imem_wdata;

  // TRNG
  uint8_t itrng_data;
  bool itrng_valid;

  uint8_t sram_error_injection_mode;

  // SRAM backdoor writes
  bool ext_iccm_we;
  bool ext_dccm_we;
  bool ext_mbox_we;
  uint32_t ext_xccm_addr;
  // 4 39-bit ECC words shoved together
  uint32_t ext_xccm_wdata[5];
};

struct caliptra_verilated_sig_out {
  bool ready_for_fuses;
  bool ready_for_mb_processing;

  // AXI Write Address Channel
  bool s_axi_awready;

  // AXI Write Data Channel
  bool s_axi_wready;

  // AXI Write Response Channel
  uint8_t s_axi_bid;
  uint8_t s_axi_bresp;
  bool s_axi_bvalid;

  // AXI Read Address Channel
  bool s_axi_arready;

  // AXI Read Data Channel
  uint8_t s_axi_rid;
  uint32_t s_axi_rdata;
  uint8_t s_axi_rresp;
  bool s_axi_rlast;
  bool s_axi_rvalid;

  uint64_t generic_output_wires;

  bool etrng_req;

  bool cptra_error_fatal;
};

struct caliptra_verilated_init_args {
  // security_state is a packed struct:
  // [2:1] = device_lifecycle (UNPROVISIONED=0, MANUFACTURING=1, PRODUCTION=3)
  // [0]   = debug_locked
  uint32_t security_state;
  uint32_t cptra_obf_key[8];
  uint32_t cptra_csr_hmac_key[16];
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
