// Licensed under the Apache-2.0 license
#pragma once

#include <caliptra_top_reg.h>

// Mirrored from the top reg file

#define CALIPTRA_SHA_ACCELERATOR_BASE_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_BASE_ADDR
#define CALIPTRA_SHA_ACCELERATOR_LOCK_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_LOCK
#define CALIPTRA_SHA_ACCELERATOR_USER_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_USER
#define CALIPTRA_SHA_ACCELERATOR_MODE_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_MODE
#define CALIPTRA_SHA_ACCELERATOR_START_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_START_ADDRESS
#define CALIPTRA_SHA_ACCELERATOR_DLEN_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_DLEN
#define CALIPTRA_SHA_ACCELERATOR_DATAIN_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_DATAIN
#define CALIPTRA_SHA_ACCELERATOR_EXECUTE_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_EXECUTE
#define CALIPTRA_SHA_ACCELERATOR_STATUS_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_STATUS
#define CALIPTRA_SHA_ACCELERATOR_DIGEST_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_DIGEST_0 // TODO: This should be an array
#define CALIPTRA_SHA_ACCELERATOR_CONTROL_ADDR CALIPTRA_TOP_REG_SHA512_ACC_CSR_CONTROL
