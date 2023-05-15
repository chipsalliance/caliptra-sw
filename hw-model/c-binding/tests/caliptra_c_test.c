// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include "caliptra_model.h"
#include "caliptra_api.h"

static struct caliptra_buffer read_file_or_die(const char* path)
{
    // Open File in Read Only Mode
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("Cannot find file %s \n", path);
        exit(-ENOENT);
    }

    struct caliptra_buffer *buffer = calloc(1, sizeof(struct caliptra_buffer));
    if (!buffer) {
        printf("Cannot allocate memory for caliptra_buffer \n");
        exit(-ENOMEM);
    }

    // Get File Size
    fseek(fp, 0L, SEEK_END);
    buffer->len = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    // Allocate Buffer Memory
    buffer->data = malloc(buffer->len);
    if (!buffer->data) {
        printf("Cannot allocate memory for buffer->data \n");
        free(buffer);
        exit(-ENOMEM);
    }

    // Read Data in Buffer
    fread((char *)buffer->data, buffer->len, 1, fp);

    return *buffer;
}

int main(void)
{
    // Initialize Params
    struct caliptra_model_init_params init_params = {
      .rom = read_file_or_die("caliptra-rom.bin"),
      .dccm = {.data = NULL, .len = 0},
      .iccm = {.data = NULL, .len = 0},
    };

    // Initialize Model
    struct caliptra_model *model;
    caliptra_model_init_default(init_params, &model);

    // Initialize Fuses (Todo: Set real fuse values)
    struct caliptra_fuses fuses = {0};
    caliptra_init_fuses(model, &fuses);

    return 0;
}
