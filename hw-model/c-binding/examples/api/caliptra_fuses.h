// Licensed under the Apache-2.0 license
#ifndef CALIPTRA_FUSES_H
#define CALIPTRA_FUSES_H

#include "caliptra_api.h"

// WARNING: THOSE APIS ARE INTENTED FOR SIMULATION ONLY.
//          SOC FW MUST HAVE NO ACCESS TO THOSE APIS.
//          A HW STATE MACHINE SHOULD BE USED TO SEND FUSE VALUES TO CALIPTRA OVER APB BUS

static inline void caliptra_fuse_write(caliptra_model *model, uint32_t offset, uint32_t data)
{
    caliptra_model_apb_write_u32(model, (offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), data);
}

static inline void caliptra_fuse_array_write(caliptra_model *model, uint32_t offset, uint32_t *data, uint32_t size)
{
    for (uint32_t idx= 0; idx < size; idx +=sizeof(uint32_t))
        caliptra_fuse_write(model, (offset + idx ), data[idx]);
}


#endif