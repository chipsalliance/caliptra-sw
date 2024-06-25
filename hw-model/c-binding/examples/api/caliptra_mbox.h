// Licensed under the Apache-2.0 license
#ifndef CALIPTRA_MBOX_H
#define CALIPTRA_MBOX_H

#include <caliptra_top_reg.h>
#include "caliptra_api.h"

static inline void caliptra_mbox_write(caliptra_model *model, uint32_t offset, uint32_t data)
{
    caliptra_model_apb_write_u32(model, (offset + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR), data);
}

static inline uint32_t caliptra_mbox_read(caliptra_model *model, uint32_t offset)
{
    uint32_t data;
    caliptra_model_apb_read_u32(model, (offset + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR), &data);
    return data;
}

static inline bool caliptra_mbox_is_lock(caliptra_model *model)
{
    return (caliptra_mbox_read(model, MBOX_CSR_MBOX_LOCK) & 1);
}

static inline void caliptra_mbox_write_cmd(caliptra_model *model, uint32_t cmd)
{
    caliptra_mbox_write(model, MBOX_CSR_MBOX_CMD, cmd);
}

static inline void caliptra_mbox_write_execute(caliptra_model *model, bool ex)
{
    caliptra_mbox_write(model, MBOX_CSR_MBOX_EXECUTE, ex);
}

static inline uint8_t caliptra_mbox_read_status(caliptra_model *model)
{
    return (uint8_t)(caliptra_mbox_read(model, MBOX_CSR_MBOX_STATUS) & 0xf);
}

static inline uint8_t caliptra_mbox_read_status_fsm(caliptra_model *model)
{
    return (uint8_t)(caliptra_mbox_read(model, MBOX_CSR_MBOX_STATUS) >> 16 & 0xf);
}

static inline uint32_t caliptra_mbox_read_dlen(caliptra_model *model)
{
    return caliptra_mbox_read(model, MBOX_CSR_MBOX_DLEN);
}

static inline void caliptra_mbox_write_dlen(caliptra_model *model, uint32_t dlen)
{
    caliptra_mbox_write(model, MBOX_CSR_MBOX_DLEN, dlen);
}


#define CALIPTRA_MBOX_STATUS_BUSY               0
#define CALIPTRA_MBOX_STATUS_DATA_READY         1
#define CALIPTRA_MBOX_STATUS_CMD_COMPLETE       2
#define CALIPTRA_MBOX_STATUS_CMD_FAILURE        3

#define CALIPTRA_MBOX_STATUS_FSM_IDLE           0
#define CALIPTRA_MBOX_STATUS_FSM_READY_FOR_CMD  1
#define CALIPTRA_MBOX_STATUS_FSM_READY_FOR_DATA 2
#define CALIPTRA_MBOX_STATUS_FSM_READY_FOR_DLEN 3
#define CALIPTRA_MBOX_STATUS_FSM_EXECUTE_SOC    4
#define CALIPTRA_MBOX_STATUS_FSM_EXECUTE_UC     6


#endif