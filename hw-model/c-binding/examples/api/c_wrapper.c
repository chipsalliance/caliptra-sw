#include "c_wrapper.h"
#include <stdint.h>
#include <stdlib.h>

caliptra_buffer create_command_hdr(uint32_t magic, uint32_t cmd, uint32_t profile) {
    struct CommandHdr {
        uint32_t magic;
        uint32_t cmd;
        uint32_t profile
    };
    
    struct CommandHdr* cmdHdr = (struct CommandHdr*)malloc(sizeof(struct CommandHdr));
    if (cmdHdr != NULL) {
        cmdHdr->magic = magic;
        cmdHdr->cmd = cmd;
        cmdHdr->profile = profile;
    }

    caliptra_buffer buffer = { .data = (const uint8_t*)cmdHdr, .len = sizeof(struct CommandHdr) };
    return buffer;
}

