// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "caliptra_api.h"

// Interface defined values
extern struct caliptra_fuses  fuses;        // Device-specific location of Caliptra fuse data
extern struct caliptra_buffer image_bundle; // Device-specific location of Caliptra firmware

int main(int argc, char *argv[])
{
    int status;

    fuses = (struct caliptra_fuses){0};

    if ((status = caliptra_init_fuses(&fuses)) != 0)
    {
        printf("Failed to init fuses: %d\n", status);
        return status;
    }

    // Initialize FSM GO
    caliptra_bootfsm_go();
    
    // Wait until ready for FW
    caliptra_ready_for_firmware();

    // Load Image Bundle
    // FW_PATH is defined on the compiler command line
    caliptra_upload_fw(&image_bundle);

    uint32_t FIPS_VERSION = 0x46505652;

    int mb_result;
    uint32_t fips_ver;
    struct caliptra_buffer buf = {
        .data = (uint8_t*)&fips_ver,
        .len = sizeof(fips_ver),
    };

    // Run Until RT is ready to receive commands
    while(1) {
        caliptra_wait();
        mb_result = caliptra_mailbox_execute(FIPS_VERSION, &buf, NULL);

        if (mb_result != -EIO)
        {
            printf("Caliptra C API Integration Test Failed: %x\n", mb_result);
            return -1;
        }

        break;
    }
    printf("Caliptra C API Integration Test Passed \n");
    return 0;
}


