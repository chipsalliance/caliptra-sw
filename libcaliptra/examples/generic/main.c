// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "test.h"
#include "caliptra_types.h"
#include "caliptra_image.h"

__attribute__((section("VPK_HASH"))) uint8_t vpk_hash[48];
__attribute__((section("OPK_HASH"))) uint8_t opk_hash[48];

static const uint32_t default_uds_seed[] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                             0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
                                             0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f };

static const uint32_t default_field_entropy[] = { 0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
                                                  0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f };

static void set_fuses(test_info* info)
{
    struct caliptra_fuses* fuses = &info->fuses;
    *fuses = (struct caliptra_fuses){0};

    memcpy(&fuses->uds_seed, default_uds_seed, sizeof(fuses->uds_seed));
    memcpy(&fuses->field_entropy, default_field_entropy, sizeof(fuses->field_entropy));

    for (int x = 0; x < SHA384_DIGEST_WORD_SIZE; x++)
    {
        // Pub key hash fuses are stored as big-endian
        fuses->owner_pk_hash[x] = __builtin_bswap32(((uint32_t*)opk_hash)[x]);
        fuses->key_manifest_pk_hash[x] = __builtin_bswap32(((uint32_t*)vpk_hash)[x]);
    }
}

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
    size_t bytes_read = fread((char *)buffer.data, 1, buffer.len, fp);

    // Make sure the read got the number of bytes we expected
    if (bytes_read != buffer.len) {
        printf("Bytes read (%ld) does not match file size (%ld)\n", bytes_read, buffer.len);
        free((void*)buffer.data);
        exit(-EIO);
    }

    return buffer;
}

int main(int argc, char *argv[])
{
    test_info info = {
        .rom = read_file_or_exit(ROM_PATH),
        .image_bundle = read_file_or_exit(FW_PATH),
        .fuses = {{0}},
    };
    set_fuses(&info);

    return run_tests(&info);
}
