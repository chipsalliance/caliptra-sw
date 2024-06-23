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
    OP_CALIPTRA_FW_LOAD            = 0x46574C44, // "FWLD"
    OP_GET_IDEV_CERT               = 0x49444543, // "IDEC"
    OP_GET_IDEV_INFO               = 0x49444549, // "IDEI"
    OP_POPULATE_IDEV_CERT          = 0x49444550, // "IDEP"
    OP_GET_LDEV_CERT               = 0x4C444556, // "LDEV"
    OP_GET_FMC_ALIAS_CERT          = 0x43455246, // "CERF"
    OP_GET_RT_ALIAS_CERT           = 0x43455252, // "CERR"
    OP_ECDSA384_VERIFY             = 0x53494756, // "SIGV"
    OP_LMS_VERIFY                  = 0x4C4D5356, // "LMSV"
    OP_STASH_MEASUREMENT           = 0x4D454153, // "MEAS"
    OP_INVOKE_DPE_COMMAND          = 0x44504543, // "DPEC"
    OP_DISABLE_ATTESTATION         = 0x4453424C, // "DSBL"
    OP_FW_INFO                     = 0x494E464F, // "INFO"
    OP_DPE_TAG_TCI                 = 0x54514754, // "TAGT"
    OP_DPE_GET_TAGGED_TCI          = 0x47544744, // "GTGD"
    OP_INCREMENT_PCR_RESET_COUNTER = 0x50435252, // "PCRR"
    OP_QUOTE_PCRS                  = 0x50435251, // "PCRQ"
    OP_EXTEND_PCR                  = 0x50435245, // "PCRE"
    OP_ADD_SUBJECT_ALT_NAME        = 0x414C544E, // "ALTN"
    OP_CERTIFY_KEY_EXTENDED        = 0x434B4558, // "CKEX"
    OP_FIPS_VERSION                = 0x46505652, // "FPVR"
    OP_SELF_TEST_START             = 0x46504C54, // "FPST"
    OP_SELF_TEST_GET_RESULTS       = 0x46504C67, // "FPGR"
    OP_SHUTDOWN                    = 0x46505344, // "FPSD"
    OP_CAPABILITIES                = 0x43415053, // "CAPS"
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

static inline uint32_t caliptra_mbox_read_execute()
{
    return caliptra_mbox_read(MBOX_CSR_MBOX_EXECUTE);
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

static inline bool caliptra_mbox_is_busy(void)
{
    return caliptra_mbox_read_status() == CALIPTRA_MBOX_STATUS_BUSY;
}

static inline uint8_t caliptra_mbox_read_status_fsm(void)
{
    return (uint8_t)(caliptra_mbox_read(MBOX_CSR_MBOX_STATUS) & MBOX_CSR_MBOX_STATUS_MBOX_FSM_PS_MASK) >> MBOX_CSR_MBOX_STATUS_MBOX_FSM_PS_LOW;
}

static inline uint32_t caliptra_mbox_read_dlen(void)
{
    return caliptra_mbox_read(MBOX_CSR_MBOX_DLEN);
}

static inline void caliptra_mbox_write_dlen(uint32_t dlen)
{
    caliptra_mbox_write(MBOX_CSR_MBOX_DLEN, dlen);
}


    

