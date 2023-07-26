// Licensed under the Apache-2.0 license

#pragma once

#include "caliptra_api.h"

// WARNING: THESE APIS ARE INTENDED FOR SIMULATION ONLY.
//          SOC FW MUST HAVE NO ACCESS TO THOSE APIS.
//          A HW STATE MACHINE SHOULD BE USED TO SEND FUSE VALUES TO CALIPTRA OVER APB BUS

static inline void caliptra_fuse_write(uint32_t offset, uint32_t data)
{
    caliptra_write_u32((offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), data);
}

static inline void caliptra_fuse_array_write(uint32_t offset, uint32_t *data, uint32_t size)
{
    for (uint32_t idx= 0; idx < size; idx +=sizeof(uint32_t))
        caliptra_fuse_write((offset + idx ), data[idx]);
}
