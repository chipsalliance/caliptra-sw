#ifndef C_WRAPPER_H
#define C_WRAPPER_H

#include <stdint.h>
#include "caliptra_api.h"

typedef struct {
    uint32_t chksum;
    uint32_t data_size;
    uint8_t data[];
} INVOKE_DPE_COMMAND;

typedef struct  {
    uint32_t magic;
    uint32_t cmd;
    uint32_t profile;
} CommandHdr;

CommandHdr create_command_hdr(uint32_t magic, uint32_t cmd, uint32_t profile);
caliptra_buffer create_invoke_dpe_command(uint32_t magic, uint32_t cmd, uint32_t profile);

#endif