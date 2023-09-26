// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "caliptra_api.h"
#include "caliptra_image.h"

struct caliptra_buffer image_bundle;
struct caliptra_fuses fuses = {0};

__attribute__((section("VPK_HASH"))) uint8_t vpk_hash[48];
__attribute__((section("OPK_HASH"))) uint8_t opk_hash[48];

static const uint32_t default_uds_seed[] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                             0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
                                             0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f };

static const uint32_t default_field_entropy[] = { 0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
                                                  0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f };

static int set_fuses()
{
    int status;

    fuses = (struct caliptra_fuses){0};

    memcpy(&fuses.uds_seed, &default_uds_seed, sizeof(default_uds_seed));
    memcpy(&fuses.field_entropy, &default_field_entropy, sizeof(default_field_entropy));

    for (int x = 0; x < SHA384_DIGEST_WORD_SIZE; x++)
    {
        fuses.owner_pk_hash[x] = __builtin_bswap32(((uint32_t*)opk_hash)[x]);
    }

    memcpy(&fuses.key_manifest_pk_hash, &vpk_hash, SHA384_DIGEST_BYTE_SIZE);

    if ((status = caliptra_init_fuses(&fuses)) != 0)
    {
        printf("Failed to init fuses: %d\n", status);
    }

    return status;
}

int main(int argc, char *argv[])
{
    int status;

    // Initialize FSM GO
    caliptra_bootfsm_go();

    set_fuses();

    // Wait until ready for FW
    caliptra_ready_for_firmware();

    // Load Image Bundle
    // FW_PATH is defined on the compiler command line
    status = caliptra_upload_fw(&image_bundle, false);

    if (status)
    {
        printf("FW Load Failed: %x\n", status);
    }
    else
    {
        printf("FW Load: OK\n");
    }

    // Run Until RT is ready to receive commands
    caliptra_wait();

    // Send a FIPS version command in async mode
    if (!status) {
        struct caliptra_fips_version version;
        // Send async
        status = caliptra_get_fips_version(&version, true);

        if (status) {
            printf("Get FIPS Version send failed: %x\n", status);
        } else {
            // Wait indefinitely for completion
            while (!caliptra_test_for_completion()){
                caliptra_wait();
            }

            status = caliptra_complete();
        }

        if (status)
        {
            printf("Get FIPS Version failed: %x\n", status);
        }
        else
        {
            printf("FIPS_VERSION = mode: 0x%x, fips_rev (0x%x, 0x%x, 0x%x), name %s \n", version.mode,
                version.fips_rev[0], version.fips_rev[1], version.fips_rev[2], version.name);
        }
    }

    // Send a stash measurement command with async off
    if (!status) {
        // Need some representative values for these, see below.
        struct caliptra_stash_measurement_req r = {0};
        struct caliptra_stash_measurement_resp c = {0};

        status = caliptra_stash_measurement(&r, &c, false);

        if (status)
        {
            printf("Stash measurement failed: %x\n", status);
        }
        else
        {
            printf("Stash measurement: OK\n");
        }
    }

    if (status)
    {
        printf("Caliptra C API Integration Test Failed: 0x%x\n", status);
        printf("Caliptra FW error non-fatal code is 0x%x\n", caliptra_read_fw_non_fatal_error());
        printf("Caliptra FW error fatal code is 0x%x\n", caliptra_read_fw_fatal_error());
    }
    else
    {
        printf("Caliptra C API Integration Test Passed!\n");
    }

    return 0;
}
