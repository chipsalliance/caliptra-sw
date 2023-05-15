// Licensed under the Apache-2.0 license
#ifndef CALIPTRA_MODEL_H
#define CALIPTRA_MODEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct caliptra_model;

struct caliptra_buffer {
  const uint8_t *data;
  size_t len;
};

struct caliptra_model_init_params {
  // The contents of the ROM
  struct caliptra_buffer rom;

  // The contents of DCCM
  struct caliptra_buffer dccm;

  // The contents of ICCM
  struct caliptra_buffer iccm;
};

enum {
  CALIPTRA_MODEL_STATUS_OK = 0,
  // more error enums here
};


// The buffers inside `params` are not used once
// caliptra_model_init_default() has returned.
int caliptra_model_init_default(struct caliptra_model_init_params params,
                                    struct caliptra_model **model);
void caliptra_model_destroy(struct caliptra_model *model);

// Read from the SoC->Caliptra APB bus
// (will cause caliptra microcontroller to execute a few instructions)
int caliptra_model_apb_read_u32(struct caliptra_model *model, uint32_t addr,
                                uint32_t *data);

// Write to the SoC->Caliptra APB bus
// (will cause caliptra microcontroller to execute a few instructions)
int caliptra_model_apb_write_u32(struct caliptra_model *model, uint32_t addr,
                                 uint32_t data);

// Step execution ahead one clock cycle
int caliptra_model_step(struct caliptra_model *model);

// Returns true if caliptra is ready to receive fuses over the APB interface
bool caliptra_model_ready_for_fuses(struct caliptra_model *model);

// Returns true if the caliptra microcontroller has signalled that it wants to
// exit (this only makes sense when running test cases on the microcontroller)
bool caliptra_model_exit_requested(struct caliptra_model *model);

// Peek at the buffer containing the "uart" output from the model. The returned
// buffer is only valid until the next API call to this model.
struct caliptra_buffer caliptra_model_output_peek(struct caliptra_model *model);

#endif // CALIPTRA_MODEL_H