//Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#define CALIPTRA_STATUS_OK 0

#ifdef __cplusplus
extern "C" {
#endif

// Memory

/**
 * caliptra_write_u32
 *
 * Writes a uint32_t value to the specified address.
 *
 * @param[in] address Memory address to write
 * @param[in] data   Data to write at address
 *
 * @return 0 if successful, other if error (TBD)
 */
int caliptra_write_u32(uint32_t address, uint32_t data);

/**
 * caliptra_read_u32
 *
 * Reads a uint32_t value from the specified address.
 *
 * @param[in] address Memory address to read
 * @param[in] data   Pointer to a uint32_t to store the data
 *
 * @return 0 if successful, other if error (TBD)
 */
int caliptra_read_u32(uint32_t address, uint32_t *data);

/**
 * caliptra_wait
 *
 * Pend the current operation.
 */
void caliptra_wait(void);

#ifdef __cplusplus
}
#endif

