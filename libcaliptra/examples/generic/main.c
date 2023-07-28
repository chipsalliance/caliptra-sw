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

    // Run Until RT is ready to receive commands
    struct caliptra_fips_version version;
    while(1) {
        caliptra_wait();
        status = caliptra_get_fips_version(&version);
        if (status)
        {
            printf("Caliptra C API Integration Test Failed: %x\n", status);
            return status;
        }

        break;
    }
    printf("Caliptra C API Integration Test Passed: \n\tFIPS_VERSION = mode: 0x%x, fips_rev (0x%x, 0x%x, 0x%x), name %s \n", version.mode,
                version.fips_rev[0], version.fips_rev[1], version.fips_rev[2], version.name);
    return 0;
}


