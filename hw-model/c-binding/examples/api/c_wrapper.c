#include "c_wrapper.h"
#include <stdint.h>
#include <stdlib.h>

caliptra_buffer create_command_hdr(uint32_t magic, uint32_t cmd, uint32_t profile) {
    struct CommandHdr {
        uint32_t magic;
        uint32_t cmd;
        uint32_t profile;
    };
    
    struct CommandHdr* cmdHdr = (struct CommandHdr*)malloc(sizeof(struct CommandHdr));
    if (cmdHdr != NULL) {
        cmdHdr->magic = magic;
        cmdHdr->cmd = cmd;
        cmdHdr->profile = profile;
    }

    

    caliptra_buffer buffer = { .data = (const uint8_t*)cmdHdr, .len = sizeof(struct CommandHdr), .chksum = calculate_caliptra_checksum(0x44504543u,(const uint8_t*)cmdHdr,sizeof(struct CommandHdr))};
    return buffer;
}

static uint32_t calculate_caliptra_checksum(uint32_t cmd, uint8_t *buffer, uint32_t len)
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
