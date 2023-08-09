// Licensed under the Apache-2.0 license

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CALIPTRA_MODEL_STATUS_OK 0

typedef struct caliptra_buffer {
  const uint8_t *data;
  uintptr_t len;
} caliptra_buffer;

typedef struct caliptra_model_init_params {
  struct caliptra_buffer rom;
  struct caliptra_buffer dccm;
  struct caliptra_buffer iccm;
} caliptra_model_init_params;

typedef struct caliptra_model {
  uint8_t _unused[0];
} caliptra_model;

struct person {
  char *name;
  int age;
};

int greet(struct person *p);

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
