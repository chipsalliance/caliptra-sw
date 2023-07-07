//Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#define CALIPTRA_STATUS_OK 0

// Memory

/**
 * caliptra_write_u32
 *
 * Writes a uint32_t value to the specified offset.
 *
 * @param[in] offset Memory offset to write
 * @param[in] data   Data to write at offset
 *
 * @return 0 if successful, other if error (TBD)
 */
int caliptra_write_u32(uint32_t offset, uint32_t data);

/**
 * caliptra_read_u32
 *
 * Writes a uint32_t value to the specified offset.
 *
 * @param[in] offset Memory offset to read
 * @param[in] data   Pointer to a uint32_t to store the data
 *
 * @return 0 if successful, other if error (TBD)
 */
int caliptra_read_u32(uint32_t offset, uint32_t *data);

/**
 * caliptra_wait
 *
 * Pend the current operation.
 */
void caliptra_wait(void);
