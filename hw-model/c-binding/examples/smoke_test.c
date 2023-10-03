// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
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
    size_t bytes_read = fread((char *)buffer.data, 1, buffer.len, fp);

    // Make sure the read got the number of bytes we expected
    if (bytes_read != buffer.len) {
        printf("Bytes read (%ld) does not match file size (%ld)\n", bytes_read, buffer.len);
        free((void*)buffer.data);
        exit(-EIO);
    }

    return buffer;
}

static void display_usage(void)
{
    printf("./smoke_test -r [rom_file] -f [fw_image_file] \n");
}

int main(int argc, char *argv[])
{
    // Process Input Arguments
    int opt;
    const char *rom_path = NULL;
    const char *fw_path = NULL;
    while((opt = getopt(argc, argv, ":r:f:")) != -1) {
        switch(opt)
        {
            case 'r':
                rom_path = optarg;
                break;
            case 'f':
                fw_path = optarg;
                break;
            case ':':
            case '?':
                display_usage();
                return -EINVAL;
        }
    }
    if (!rom_path || !fw_path) {
        display_usage();
        return -EINVAL;
    }

    // Initialize Params
    struct caliptra_model_init_params init_params = {
      .rom = read_file_or_die(rom_path),
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
    struct caliptra_buffer image_bundle = read_file_or_die(fw_path);
    caliptra_upload_fw(model, &image_bundle);

    // Run Until RT is ready to receive commands
    while(1) {
        caliptra_model_step(model);
        struct caliptra_buffer buffer = caliptra_model_output_peek(model);
        if (strstr(buffer.data, "Caliptra RT listening for mailbox commands..."))
            break;
    }
    printf("Caliptra C Smoke Test Passed \n");
    return 0;
}


