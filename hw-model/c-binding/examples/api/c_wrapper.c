#include "c_wrapper.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


uint32_t calculate_caliptra_checksum(uint32_t cmd, uint8_t *buffer, uint32_t len)
{
    uint32_t i, sum = 0;

    if ((buffer == NULL) && (len != 0))
    {
        return 0;
    }

    for (i = 0; i < sizeof(uint32_t); i++)
    {
        sum += ((uint8_t*)(&cmd))[i];
    }

    for (i = 0; i < len; i++)
    {
        sum += buffer[i];
    }

    return (0 - sum);
}


caliptra_buffer create_invoke_dpe_command(uint8_t* data, uint32_t data_size) {

    const uint32_t OP_INVOKE_DPE_COMMAND = 0x44504543;

    INVOKE_DPE_COMMAND* invokeCmd = (INVOKE_DPE_COMMAND*)malloc(sizeof(INVOKE_DPE_COMMAND));
    if (invokeCmd != NULL) {
        invokeCmd->data_size = data_size;

        memcpy(invokeCmd->data, data, data_size);
        invokeCmd->chksum = calculate_caliptra_checksum(OP_INVOKE_DPE_COMMAND, (uint8_t*)invokeCmd, sizeof(INVOKE_DPE_COMMAND) - sizeof(uint32_t));

    }

    caliptra_buffer buffer = {
        .data = (const uint8_t*)invokeCmd,
        .len = sizeof(INVOKE_DPE_COMMAND)
    };

    return buffer;
}