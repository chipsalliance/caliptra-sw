#include "c_wrapper.h"
#include <stdint.h>
#include <stdlib.h>

uint32_t calculate_caliptra_checksum(uint32_t cmd, uint8_t *buffer, uint32_t len)
{
    uint32_t i, sum = 0;

    if ((buffer == NULL) && (len != 0))
    {
        // Don't respect bad parameters
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

CommandHdr create_command_hdr(uint32_t magic, uint32_t cmd, uint32_t profile) {
    CommandHdr* cmdHdr = (CommandHdr*)malloc(sizeof(CommandHdr));
    if (cmdHdr != NULL) {
        cmdHdr->magic = magic;
        cmdHdr->cmd = cmd;
        cmdHdr->profile = profile;
    }

    return *cmdHdr;
}

caliptra_buffer create_invoke_dpe_command(uint32_t magic, uint32_t cmd, uint32_t profile) {
    CommandHdr cmdHdr = create_command_hdr(magic, cmd, profile);

    INVOKE_DPE_COMMAND* invokeCmd = (INVOKE_DPE_COMMAND*)malloc(sizeof(INVOKE_DPE_COMMAND) + sizeof(CommandHdr));
    if (invokeCmd != NULL) {
        invokeCmd->data_size = sizeof(CommandHdr);
        invokeCmd->chksum = calculate_caliptra_checksum(0x44504543u, (uint8_t*)&cmdHdr, sizeof(CommandHdr));
        memcpy(invokeCmd->data, &cmdHdr, sizeof(CommandHdr));
    }

    caliptra_buffer buffer = {
        .data = (const uint8_t*)invokeCmd,
        .len = sizeof(INVOKE_DPE_COMMAND) + sizeof(CommandHdr)
    };

    return buffer;
}
