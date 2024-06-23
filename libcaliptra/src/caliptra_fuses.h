// Licensed under the Apache-2.0 license

#pragma once

#include "caliptra_api.h"

#define MBOX_PAUSER_SLOTS (5)

// WARNING: THESE APIS ARE INTENDED FOR SIMULATION ONLY.
//          SOC FW MUST HAVE NO ACCESS TO THOSE APIS.
//          A HW STATE MACHINE SHOULD BE USED TO SEND FUSE VALUES TO CALIPTRA OVER APB BUS

static inline void caliptra_generic_and_fuse_write(uint32_t offset, uint32_t data)
{
    caliptra_write_u32((offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), data);
}

static inline uint32_t caliptra_generic_and_fuse_read(uint32_t offset)
{
    uint32_t data;
    caliptra_read_u32((offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), &data);
    return data;
}

static inline void caliptra_fuse_array_write(uint32_t offset, uint32_t *data, size_t size)
{
    for (uint32_t idx = 0; idx < size; idx ++)
    {
        caliptra_generic_and_fuse_write((offset + (idx * sizeof(uint32_t))), data[idx]);
    }
}

static inline uint32_t caliptra_read_fw_error_non_fatal(void)
{
    return caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_FW_ERROR_NON_FATAL);
}

static inline uint32_t caliptra_read_fw_error_fatal(void)
{
    return caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_FW_ERROR_FATAL);
}

static inline uint32_t caliptra_read_dbg_manuf_serv() 
{
    return caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_DBG_MANUF_SERVICE_REG);    
}


static inline void caliptra_wdt_cfg_write(uint64_t data)
{
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_WDT_CFG_0, (uint32_t)data);
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_WDT_CFG_1, (uint32_t)(data >> 32));
}


static inline void caliptra_write_itrng_entropy_low_threshold(uint16_t data)
{
    uint32_t val = caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0);
    val &= ~GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0_LOW_THRESHOLD_MASK;
    val |= data & GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0_LOW_THRESHOLD_MASK;
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0, val);
}

static inline void caliptra_write_itrng_entropy_high_threshold(uint16_t data)
{
    uint32_t val = caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0);
    val &= ~GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0_HIGH_THRESHOLD_MASK;
    val |= (data << GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0_HIGH_THRESHOLD_LOW)
            & GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0_HIGH_THRESHOLD_MASK;
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_0, val);
}

static inline void caliptra_write_itrng_entropy_repetition_count(uint16_t data)
{
    uint32_t val = caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_1);
    val &= ~GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_1_REPETITION_COUNT_MASK;
    val |= data & GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_1_REPETITION_COUNT_MASK;
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_ITRNG_ENTROPY_CONFIG_1, val);
}

// NOTE: Is the responsibility of the caller to ensure the index does not exceed MBOX_PAUSER_SLOTS
static inline bool caliptra_read_mbox_pauser_lock(uint8_t idx)
{
    return caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_MBOX_PAUSER_LOCK_0 + (sizeof(uint32_t) * idx)) != 0;
}

// NOTE: Is the responsibility of the caller to ensure the index does not exceed MBOX_PAUSER_SLOTS
static inline void caliptra_set_mbox_pauser_lock(uint8_t idx)
{
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_MBOX_PAUSER_LOCK_0 + (sizeof(uint32_t) * idx), 0x1);
}

// NOTE: Is the responsibility of the caller to ensure the index does not exceed MBOX_PAUSER_SLOTS
static inline void caliptra_write_mbox_valid_pauser(uint8_t idx, uint32_t data)
{
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_MBOX_VALID_PAUSER_0 + (sizeof(uint32_t) * idx), data);
}

static inline bool caliptra_read_fuse_pauser_lock()
{
    return caliptra_generic_and_fuse_read(GENERIC_AND_FUSE_REG_CPTRA_FUSE_PAUSER_LOCK) != 0;
}

static inline void caliptra_set_fuse_pauser_lock()
{
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_FUSE_PAUSER_LOCK, 0x1);
}

static inline void caliptra_write_fuse_valid_pauser(uint32_t data)
{
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_FUSE_VALID_PAUSER, data);
}

static inline void caliptra_write_dbg_manuf_serv(uint32_t data) 
{
    // Set Manuf service reg
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_CPTRA_DBG_MANUF_SERVICE_REG, data);    
}
