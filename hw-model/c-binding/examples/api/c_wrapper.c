#include "c_wrapper.h"
#include <stdint.h>
#include <stdlib.h>

caliptra_buffer create_command_hdr(uint32_t magic, uint32_t cmd, uint16_t major, uint16_t minor) {
    struct CommandHdr {
        uint32_t magic;
        uint32_t cmd;
        struct {
            uint16_t major_version;
            uint16_t minor_version;
        } profile;
    };
    
    struct CommandHdr* cmdHdr = (struct CommandHdr*)malloc(sizeof(struct CommandHdr));
    if (cmdHdr != NULL) {
        cmdHdr->magic = magic;
        cmdHdr->cmd = cmd;
        cmdHdr->profile.major_version = major;
        cmdHdr->profile.minor_version = minor;
    }

    caliptra_buffer buffer = { .data = (const uint8_t*)cmdHdr, .len = sizeof(struct CommandHdr) };
    return buffer;
}

