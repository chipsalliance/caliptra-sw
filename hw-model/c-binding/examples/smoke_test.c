// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "caliptra_model.h"
#include "api/caliptra_api.h"

static struct caliptra_buffer read_file_or_die(const char* path)
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

void main(void)
{
    // Initialize Params
    struct caliptra_model_init_params init_params = {
      .rom = read_file_or_die("fw_test/caliptra-rom.bin"),
      .dccm = {.data = NULL, .len = 0},
      .iccm = {.data = NULL, .len = 0},
    };

    // Initialize Model
    struct caliptra_model *model;
    caliptra_model_init_default(init_params, &model);

    // Initialize Fuses (Todo: Set real fuse values)
    struct caliptra_fuses fuses = {0};
    caliptra_init_fuses(model, &fuses);

    // Initialize FSM GO
    caliptra_bootfsm_go(model);
    caliptra_model_step(model);

    // Step until read for FW
    while (!caliptra_model_ready_for_fw(model)) {
        caliptra_model_step(model);
    }

    // Load Image Bundle
    struct caliptra_buffer image_bundle = read_file_or_die("fw_test/image-bundle.bin");
    caliptra_upload_fw(model, &image_bundle);

    // Run Until RT is ready to receive commands
    while(1) {
        caliptra_model_step(model);
        struct caliptra_buffer buffer = caliptra_model_output_peek(model);
        if (strstr(buffer.data, "Caliptra RT listening for mailbox commands..."))
            break;
    }
    printf("Caliptra C Smoke Test Passed \n");
}


