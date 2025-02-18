// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>

#include "caliptra_types.h"

typedef struct test_info {
  struct caliptra_buffer rom;
  struct caliptra_buffer image_bundle;
  struct caliptra_fuses fuses;
  uint32_t apb_pauser;
} test_info;

#ifdef __cplusplus
extern "C" {
#endif

int run_tests(const test_info* info);

#ifdef __cplusplus
}
#endif
