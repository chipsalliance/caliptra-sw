// Licensed under the Apache-2.0 license
#pragma once

/**
 * Mailbox helper functions
 *
 * All of the below functions map to register reads and writes.
 *
 * TODO: Investigate interrupts for notification on mailbox
 *       command completion.
 */

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

static inline void caliptra_mbox_write(uint32_t offset, uint32_t data)
{
    caliptra_write_u32((offset + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR), data);
}

static inline uint32_t caliptra_mbox_read(uint32_t offset)
{
    uint32_t data;
    caliptra_read_u32((offset + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR), &data);
    return data;
}

static inline bool caliptra_mbox_is_lock()
{
    return (caliptra_mbox_read(MBOX_CSR_MBOX_LOCK) & MBOX_CSR_MBOX_LOCK_LOCK_MASK);
}

static inline void caliptra_mbox_write_cmd(uint32_t cmd)
{
    caliptra_mbox_write(MBOX_CSR_MBOX_CMD, cmd);
}

static inline void caliptra_mbox_write_execute(bool ex)
{
    caliptra_mbox_write(MBOX_CSR_MBOX_EXECUTE, ex);
}

static inline uint8_t caliptra_mbox_write_execute_busy_wait(bool ex)
{
    caliptra_mbox_write(MBOX_CSR_MBOX_EXECUTE, ex);
    uint8_t status;
    while((status = (uint8_t)(caliptra_mbox_read(MBOX_CSR_MBOX_STATUS) & MBOX_CSR_MBOX_STATUS_STATUS_MASK)) == CALIPTRA_MBOX_STATUS_BUSY)
    {
        caliptra_wait();
    }

    return status;
}

static inline uint8_t caliptra_mbox_read_status(void)
{
    return (uint8_t)(caliptra_mbox_read(MBOX_CSR_MBOX_STATUS) & MBOX_CSR_MBOX_STATUS_STATUS_MASK);
}

static inline uint8_t caliptra_mbox_read_status_fsm(void)
{
    return (uint8_t)(caliptra_mbox_read(MBOX_CSR_MBOX_STATUS) >> 16 & MBOX_CSR_MBOX_STATUS_STATUS_MASK);
}

static inline uint32_t caliptra_mbox_read_dlen(void)
{
    return caliptra_mbox_read(MBOX_CSR_MBOX_DLEN);
}

static inline void caliptra_mbox_write_dlen(uint32_t dlen)
{
    caliptra_mbox_write(MBOX_CSR_MBOX_DLEN, dlen);
}
