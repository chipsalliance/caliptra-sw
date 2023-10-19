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

static inline uint32_t caliptra_fuse_read(uint32_t offset)
{
    uint32_t data;
    caliptra_read_u32((offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), &data);
    return data;
}

static inline void caliptra_fuse_array_write(uint32_t offset, uint32_t *data, size_t size)
{
    for (uint32_t idx = 0; idx < size; idx ++)
    {
        caliptra_fuse_write((offset + (idx * sizeof(uint32_t))), data[idx]);
    }
}

static inline uint32_t caliptra_read_fw_error_non_fatal(void)
{
    return caliptra_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_FW_ERROR_NON_FATAL);
}

static inline uint32_t caliptra_read_fw_error_fatal(void)
{
    return caliptra_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_FW_ERROR_FATAL);
}

static inline void caliptra_wdt_cfg_write(uint64_t data)
{
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_WDT_CFG_0, (uint32_t)data);
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_WDT_CFG_1, (uint32_t)(data >> 32));
}
