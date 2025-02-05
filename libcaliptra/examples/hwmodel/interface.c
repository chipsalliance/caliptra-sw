//Licensed under the Apache-2.0 license

#define HWMODEL 1

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "caliptra_model.h"

#define CALIPTRA_STATUS_OK 0

// Implementation specifics

struct caliptra_model *model = NULL;

static struct caliptra_model_init_params init_params;


// ONLY for testing. Not part of actual libcaliptra interface
void testbench_reinit(void)
{
    if (model) {
        caliptra_model_destroy(model);
        model = NULL;
    }
}

void hwmod_init(struct caliptra_buffer rom) {
  // slice::from_raw_parts can panic when the pointer is NULL
  uint8_t empty[0];
    struct caliptra_model_init_params params = {
        .rom = rom,
        .dccm = {.data = empty, .len = 0},
        .iccm = {.data = empty, .len = 0},
        .security_state = CALIPTRA_SEC_STATE_DBG_LOCKED_MANUFACTURING,
    };
    init_params = params;
}

struct caliptra_model* hwmod_get_or_init(void)
{
    if (model == NULL)
    {
        int status = caliptra_model_init_default(init_params, &model);

        if (status != CALIPTRA_STATUS_OK) {
            return NULL;
        }
    }

    return model;
}

// Memory

/**
 * caliptra_write_u32
 *
 * Writes a uint32_t value to the specified address.
 *
 * @param[in] address Memory address to write
 * @param[in] data Data to write at address
 *
 * @return 0 if successful, other if error (TBD)
 */
int caliptra_write_u32(uint32_t address, uint32_t data)
{
    struct caliptra_model *m = hwmod_get_or_init();

    int result = caliptra_model_apb_write_u32(m, address, (int)data);

    caliptra_model_step(m);

    return result;
}

/**
 * caliptra_read_u32
 *
 * Reads a uint32_t value from the specified address.
 *
 * @param[in] address Memory address to read
 * @param[in] data Pointer to a uint32_t to store the data
 *
 * @return 0 if successful, other if error (TBD)
 */
int caliptra_read_u32(uint32_t address, uint32_t *data)
{
    return caliptra_model_apb_read_u32(hwmod_get_or_init(), address, (uint*)data);
}

/**
 * caliptra_wait
 *
 * Pend the current operation.
 */
void caliptra_wait(void)
{
    caliptra_model_step(hwmod_get_or_init());
}
