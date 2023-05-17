// Licensed under the Apache-2.0 license
#ifndef CALIPTRA_FUSES_H
#define CALIPTRA_FUSES_H

#include "caliptra_api.h"

#define CALIPTRA_FUSE_WRITE(model, offset, data) \
    do { \
        caliptra_model_apb_write_u32(model, (offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), data); \
    } while(0)

#define CALIPTRA_FUSE_ARRAY_WRITE(model, offset, data, size) \
    do { \
        for (uint32_t _i = 0; _i < (size / sizeof(uint32_t)); _i++) \
            CALIPTRA_FUSE_WRITE(model, (offset + (_i * sizeof(uint32_t))), data[_i]); \
    } while(0)


#endif