// Licensed under the Apache-2.0 license
#ifndef CALIPTRA_MBOX_H
#define CALIPTRA_MBOX_H

#include "caliptra_api.h"
#define CALIPTRA_MBOX_WRITE(model, offset, data) \
    do { \
        caliptra_model_apb_write_u32(model, (offset + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR), data); \
    } while(0)

#define CALIPTRA_MBOX_READ(model, offset) \
    ({ \
        uint32_t _ret; \
        caliptra_model_apb_read_u32(model, (offset + CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR), &_ret); \
        _ret; \
    })

#define CALIPTRA_MBOX_IS_LOCK(model) \
    ({ \
        uint32_t _lock = CALIPTRA_MBOX_READ(model, MBOX_CSR_MBOX_LOCK); \
        _lock &= 1; \
    })

#define CALIPTRA_MBOX_WRITE_CMD(model, cmd) \
    do { \
        CALIPTRA_MBOX_WRITE(model, MBOX_CSR_MBOX_CMD, cmd); \
    } while(0)

#define CALIPTRA_MBOX_WRITE_EXECUTE(model, ex) \
    do { \
        CALIPTRA_MBOX_WRITE(model, MBOX_CSR_MBOX_EXECUTE, ex); \
    } while(0)

#define CALIPTRA_MBOX_READ_STATUS(model) \
    ({ \
        uint32_t _status = CALIPTRA_MBOX_READ(model, MBOX_CSR_MBOX_STATUS); \
        _status &= 0xf; \
    })

#define CALIPTRA_MBOX_READ_STATUS_FSM(model) \
    ({ \
        uint32_t _status_fsm = CALIPTRA_MBOX_READ(model, MBOX_CSR_MBOX_STATUS) >> 16; \
        _status_fsm &= 0xf; \
    })

#define CALIPTRA_MBOX_READ_DLEN(model) \
    ({ \
        uint32_t _dlen = CALIPTRA_MBOX_READ(model, MBOX_CSR_MBOX_DLEN); \
        _dlen; \
    })

#define CALIPTRA_MBOX_WRITE_DLEN(model, dlen) \
    do { \
        CALIPTRA_MBOX_WRITE(model, MBOX_CSR_MBOX_DLEN, dlen); \
    } while(0)


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