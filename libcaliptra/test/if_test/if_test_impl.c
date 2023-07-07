//Licensed under the Apache-2.0 license

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "caliptra_api.h"
#include "caliptra_if.h"

// Memory
int caliptra_write_u32(uint32_t offset, uint32_t data)
{
    return CALIPTRA_STATUS_OK;
}

int caliptra_read_u32(uint32_t offset, uint32_t *data)
{
    return 0x0ACEFACE;
}

// Control

void caliptra_wait(void)
{
    // Execute some desired stall step, such as yield()
}
