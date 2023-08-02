//Licensed under the Apache-2.0 license

#define HWMODEL 1

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#include "caliptra_model.h"
#include "caliptra_api.h"

#define CALIPTRA_STATUS_OK 0

// Implementation specifics

struct caliptra_model_init_params init_params;
struct caliptra_fuses fuses = {0};
struct caliptra_buffer image_bundle;

static bool caliptra_model_init_complete = false;

static struct caliptra_buffer read_file_or_exit(const char* path)
{
    // Open File in Read Only Mode
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("Cannot find file %s \n", path);
        exit(-ENOENT);
    }

    struct caliptra_buffer buffer = {0};

    // Get File Size
    fseek(fp, 0L, SEEK_END);
    buffer.len = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    // Allocate Buffer Memory
    buffer.data = malloc(buffer.len);
    if (!buffer.data) {
        printf("Cannot allocate memory for buffer->data \n");
        exit(-ENOMEM);
    }

    // Read Data in Buffer
    fread((char *)buffer.data, buffer.len, 1, fp);

    return buffer;
}

struct caliptra_model* hwmod_get_or_init(void)
{
    const char *rom_path = ROM_PATH;
    const char *fw_path = FW_PATH;
    static struct caliptra_model *model = NULL;

    if (model == NULL)
    {
        // Initialize Params
        // HW model only
        // ROM_PATH is defined on the compiler command line
        struct caliptra_model_init_params init_params = {
          .rom = read_file_or_exit(rom_path),
          .dccm = {.data = NULL, .len = 0},
          .iccm = {.data = NULL, .len = 0},
        };

        image_bundle = (struct caliptra_buffer)read_file_or_exit(fw_path);

        int status = caliptra_model_init_default(init_params, &model);
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
    return caliptra_model_apb_read_u32(hwmod_get_or_init(), address, (int*)data);
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
