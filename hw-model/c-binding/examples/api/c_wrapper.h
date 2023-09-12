#ifndef C_WRAPPER_H
#define C_WRAPPER_H

#include <stdint.h>
#include "caliptra_api.h"

#define DPE_REQ_MAX_SIZE 512

typedef struct {
    uint32_t chksum;
    uint32_t data_size;
    uint8_t data[DPE_REQ_MAX_SIZE];
} INVOKE_DPE_COMMAND;

caliptra_buffer create_invoke_dpe_command(uint8_t* data, uint32_t length);

#endif
