// Licensed under the Apache-2.0 license
#pragma once

#define CALIPTRA_MAILBOX_MAX_SIZE (128u * 1024u)

enum caliptra_mailbox_status {
    CALIPTRA_MBOX_STATUS_BUSY         = 0,
    CALIPTRA_MBOX_STATUS_DATA_READY   = 1,
    CALIPTRA_MBOX_STATUS_CMD_COMPLETE = 2,
    CALIPTRA_MBOX_STATUS_CMD_FAILURE  = 3,
};

enum caliptra_mailbox_fsm_states {
    CALIPTRA_MBOX_STATUS_FSM_IDLE           = 0,
    CALIPTRA_MBOX_STATUS_FSM_READY_FOR_CMD  = 1,
    CALIPTRA_MBOX_STATUS_FSM_READY_FOR_DATA = 2,
    CALIPTRA_MBOX_STATUS_FSM_READY_FOR_DLEN = 3,
    CALIPTRA_MBOX_STATUS_FSM_EXECUTE_SOC    = 4,
    CALIPTRA_MBOX_STATUS_FSM_EXECUTE_UC     = 6,
};

enum mailbox_command {
    OP_CALIPTRA_FW_LOAD          = 0x46574C44, // "FWLD"
    OP_GET_IDEV_CSR              = 0x49444556, // "IDEV"
    OP_GET_LDEV_CERT             = 0x4C444556, // "LDEV"
    OP_ECDSA384_VERIFY           = 0x53494756, // "SIGV"
    OP_STASH_MEASUREMENT         = 0x4D454153, // "MEAS"
    OP_DISABLE_ATTESTATION       = 0x4453424C, // "DSBL"
    OP_INVOKE_DPE_COMMAND        = 0x44504543, // "DPEC"
    OP_FIPS_VERSION              = 0x46505652, // "FPVR"
};

struct parcel {
    enum mailbox_command  command;
    uint8_t              *tx_buffer;
    size_t                tx_bytes;
    uint8_t              *rx_buffer;
    size_t                rx_bytes;
};

enum mailbox_results {
    SUCCESS        = 0x00000000,
    BAD_VENDOR_SIG = 0x56534947, // "VSIG"
    BAD_OWNER_SIG  = 0x4F534947, // "OSIG"
    BAD_SIG        = 0x42534947, // "BSIG"
    BAD_IMAGE      = 0x42494D47, // "BIMG"
    BAD_CHKSUM     = 0x4243484B, // "BCHK"
};

/**
 * Mailbox helper functions
 *
 * All of the below functions map to register reads and writes.
 *
 * TODO: Investigate interrupts for notification on mailbox
 *       command completion.
 */
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
