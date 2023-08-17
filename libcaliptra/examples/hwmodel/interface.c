//Licensed under the Apache-2.0 license

#define HWMODEL 1

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/evp.h>

#include <caliptra_top_reg.h>

#include "caliptra_model.h"
#include "caliptra_api.h"
#include "caliptra_fuses.h"
#include "caliptra_image.h"

#define CALIPTRA_STATUS_OK 0

// Implementation specifics

struct caliptra_model_init_params init_params;
struct caliptra_fuses fuses = {0};
struct caliptra_buffer image_bundle;

static bool caliptra_model_init_complete = false;

// Interface defined values
extern struct caliptra_fuses  fuses;        // Device-specific location of Caliptra fuse data
extern struct caliptra_buffer image_bundle; // Device-specific location of Caliptra firmware

static const uint32_t default_uds_seed[] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                             0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
                                             0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f };

static const uint32_t default_field_entropy[] = { 0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
                                                  0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f };
/**
 * caliptra_ready_for_fuses
 *
 * Reports if the Caliptra hardware is ready for fuse data
 *
 * @return bool True if ready, false otherwise
 */
bool caliptra_ready_for_fuses(void)
{
    uint32_t status;

    caliptra_read_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS, &status);

    if ((status & GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_FUSES_MASK) != 0) {
        return true;
    }

    return false;
}

/**
 * caliptra_init_fuses
 *
 * Initialize fuses based on contents of "fuses" argument
 *
 * @param[in] fuses Valid caliptra_fuses structure
 *
 * @return int 0 if successful, -EINVAL if fuses is null, -EPERM if caliptra is not ready for fuses, -EIO if still ready after fuses are written
 */
int caliptra_init_fuses(struct caliptra_fuses *fuses)
{
    // Parameter check
    if (!fuses)
    {
        return -EINVAL;
    }

    // Check whether caliptra is ready for fuses
    if (!caliptra_ready_for_fuses())
        return -EPERM;

    // Write Fuses
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_UDS_SEED_0, fuses->uds_seed, ARRAY_SIZE(fuses->uds_seed));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_FIELD_ENTROPY_0, fuses->field_entropy, ARRAY_SIZE(fuses->field_entropy));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_0, fuses->key_manifest_pk_hash, ARRAY_SIZE(fuses->key_manifest_pk_hash));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_MASK, fuses->key_manifest_pk_hash_mask);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_OWNER_PK_HASH_0, fuses->owner_pk_hash, ARRAY_SIZE(fuses->owner_pk_hash));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_FMC_KEY_MANIFEST_SVN, fuses->fmc_key_manifest_svn);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_RUNTIME_SVN_0, fuses->runtime_svn, ARRAY_SIZE(fuses->runtime_svn));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_ANTI_ROLLBACK_DISABLE, (uint32_t)fuses->anti_rollback_disable);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_IDEVID_CERT_ATTR_0, fuses->idevid_cert_attr, ARRAY_SIZE(fuses->idevid_cert_attr));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_IDEVID_MANUF_HSM_ID_0, fuses->idevid_manuf_hsm_id, ARRAY_SIZE(fuses->idevid_manuf_hsm_id));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_LIFE_CYCLE, (uint32_t)fuses->life_cycle);

    // Write to Caliptra Fuse Done
    caliptra_write_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FUSE_WR_DONE, 1);

    // No longer ready for fuses
    if (caliptra_ready_for_fuses())
        return -EIO;

    return 0;
}

/**
 * set_fuses
 *
 * This function exists to account for the fact that the simulator and
 * FPGA do not have true OTP fuses and, as such, need to be set during
 * early startup.
 *
 * The expectation at actual time of use is that the SOC will have OTP
 * fuses (and the associated key digests) programmed during manufacturing
 * and as such users will not perform these digests and writes.
 */
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

        int status = caliptra_model_init_default(init_params, &model);

        image_bundle = (struct caliptra_buffer)read_file_or_exit(fw_path);

        if (image_bundle.data == NULL)
        {
            return NULL;
        }

        struct caliptra_image_manifest *image = (struct caliptra_image_manifest *)image_bundle.data;

        if (status = set_fuses(image))
        {
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
