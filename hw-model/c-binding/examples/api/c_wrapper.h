#ifndef C_WRAPPER_H
#define C_WRAPPER_H

#include <stdint.h>
#include "caliptra_api.h"

caliptra_buffer create_command_hdr(uint32_t magic, uint32_t cmd, uint32_t profile);

#endif
