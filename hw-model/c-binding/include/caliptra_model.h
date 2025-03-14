// Licensed under the Apache-2.0 license

#ifndef HW_MODEL_C_BINDING_OUT_CALIPTRA_MODEL_H
#define HW_MODEL_C_BINDING_OUT_CALIPTRA_MODEL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CALIPTRA_SEC_STATE_DBG_UNLOCKED_UNPROVISIONED 0

#define CALIPTRA_SEC_STATE_DBG_LOCKED_MANUFACTURING 5

#define CALIPTRA_SEC_STATE_DBG_UNLOCKED_PRODUCTION 3

#define CALIPTRA_SEC_STATE_DBG_LOCKED_PRODUCTION 7

#define CALIPTRA_MODEL_STATUS_OK 0

typedef struct caliptra_buffer {
  const uint8_t *data;
  uintptr_t len;
} caliptra_buffer;

typedef struct caliptra_model_init_params {
  struct caliptra_buffer rom;
  struct caliptra_buffer dccm;
  struct caliptra_buffer iccm;
  uint8_t security_state;
  uint32_t soc_user;
} caliptra_model_init_params;

typedef struct caliptra_model {
  uint8_t _unused[0];
} caliptra_model;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * # Safety
 */
int caliptra_model_init_default(struct caliptra_model_init_params params,
                                struct caliptra_model **model);

/**
 * # Safety
 */
void caliptra_model_destroy(struct caliptra_model *model);

/**
 * # Safety
 */
int caliptra_model_apb_read_u32(struct caliptra_model *model,
                                unsigned int addr,
                                unsigned int *data);

/**
 * # Safety
 */
int caliptra_model_apb_write_u32(struct caliptra_model *model,
                                 unsigned int addr,
                                 unsigned int data);

/**
 * # Safety
 */
bool caliptra_model_ready_for_fuses(struct caliptra_model *model);

/**
 * # Safety
 */
bool caliptra_model_ready_for_fw(struct caliptra_model *model);

/**
 * # Safety
 */
int caliptra_model_step(struct caliptra_model *model);

/**
 * # Safety
 */
bool caliptra_model_exit_requested(struct caliptra_model *model);

/**
 * # Safety
 */
struct caliptra_buffer caliptra_model_output_peek(struct caliptra_model *model);

/**
 * # Safety
 */
void caliptra_model_step_until_boot_status(struct caliptra_model *model, unsigned int boot_status);

/**
 * # Safety
 */
void caliptra_model_set_apb_pauser(struct caliptra_model *model, unsigned int pauser);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* HW_MODEL_C_BINDING_OUT_CALIPTRA_MODEL_H */
