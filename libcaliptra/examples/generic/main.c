// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "caliptra_api.h"

// Interface defined values
extern struct caliptra_fuses  fuses;        // Device-specific location of Caliptra fuse data
extern struct caliptra_buffer image_bundle; // Device-specific location of Caliptra firmware

static const uint32_t default_uds_seed[] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                             0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
                                             0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f };

static const uint32_t default_field_entropy[] = { 0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
                                                  0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f };

static int set_fuses(struct caliptra_image_manifest *image)
{
    int status;

    const EVP_MD *md;
    EVP_MD_CTX *ctx;

    uint32_t md_vendor_pubkey[SHA384_DIGEST_WORD_SIZE];
    uint32_t md_owner_pubkey[SHA384_DIGEST_WORD_SIZE];
    int      mdlen;

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("SHA384");

    if (!md)
    {
        printf("Failed to acquire SHA384 digest\n");
        return -1;
    }

    ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, &image->preamble.vendor_pub_keys, sizeof(struct image_vendor_pubkeys));
    EVP_DigestFinal_ex(ctx, (unsigned char*)md_vendor_pubkey, &mdlen);
    EVP_MD_CTX_destroy(ctx);

    if (mdlen != SHA384_DIGEST_BYTE_SIZE)
    {
        printf("SHA384 digest from OpenSSL is not the correct size! e: %u a: %u", SHA384_DIGEST_BYTE_SIZE, mdlen);
    }

    ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, &image->preamble.owner_pub_keys, sizeof(struct image_owner_pubkeys));
    EVP_DigestFinal_ex(ctx, (unsigned char*)md_owner_pubkey, &mdlen);
    EVP_MD_CTX_destroy(ctx);

    if (mdlen != SHA384_DIGEST_BYTE_SIZE)
    {
        printf("SHA384 digest from OpenSSL is not the correct size! e: %u a: %u", SHA384_DIGEST_BYTE_SIZE, mdlen);
    }

    fuses = (struct caliptra_fuses){0};

    memcpy(&fuses.uds_seed, &default_uds_seed, sizeof(default_uds_seed));
    memcpy(&fuses.field_entropy, &default_field_entropy, sizeof(default_field_entropy));
    memcpy(&fuses.key_manifest_pk_hash, &md_vendor_pubkey, SHA384_DIGEST_BYTE_SIZE);

    for (int x = 0; x < SHA384_DIGEST_WORD_SIZE; x++)
    {
        fuses.owner_pk_hash[x] = __builtin_bswap32(((uint32_t*)md_owner_pubkey)[x]);
    }

    if ((status = caliptra_init_fuses(&fuses)) != 0)
    {
        printf("Failed to init fuses: %d\n", status);
    }

    return status;
}

int main(int argc, char *argv[])
{
    int status;

    struct caliptra_image_manifest *image = (struct caliptra_image_manifest *)image_bundle.data;

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


