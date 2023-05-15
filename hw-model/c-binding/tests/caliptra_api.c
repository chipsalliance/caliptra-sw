// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <errno.h>
#include <caliptra_top_reg.h>
#include "caliptra_api.h"

#define CALIPTRA_FUSE_WRITE(model, offset, data) \
    do { \
        caliptra_model_apb_write_u32(model, (offset + CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_BASE_ADDR), data); \
    } while(0)

#define CALIPTRA_FUSE_ARRAY_WRITE(model, offset, data, size) \
    do { \
        for (uint32_t _i = 0; _i < (size / sizeof(uint32_t)); _i++) \
            CALIPTRA_FUSE_WRITE(model, (offset + (_i * sizeof(uint32_t))), data[_i]); \
    } while(0)


int caliptra_init_fuses(struct caliptra_model *model, struct caliptra_fuses *fuses)
{
    // Parameter check
    if (!model || !fuses) {
        return -EINVAL;
    }

    // Check whether caliptra is ready for fuses
    if (!caliptra_model_ready_for_fuses(model))
        return -EPERM;

    // Write Fuses
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_UDS_SEED_0, fuses->uds_seed, sizeof(fuses->uds_seed));
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_FIELD_ENTROPY_0, fuses->field_entropy, sizeof(fuses->field_entropy));
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_0, fuses->key_manifest_pk_hash, sizeof(fuses->key_manifest_pk_hash));
    CALIPTRA_FUSE_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_MASK, fuses->key_manifest_pk_hash_mask);
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_OWNER_PK_HASH_0, fuses->owner_pk_hash, sizeof(fuses->owner_pk_hash));
    CALIPTRA_FUSE_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_FMC_KEY_MANIFEST_SVN, fuses->fmc_key_manifest_svn);
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_FMC_KEY_MANIFEST_SVN, fuses->runtime_svn, sizeof(fuses->runtime_svn));
    CALIPTRA_FUSE_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_ANTI_ROLLBACK_DISABLE, (uint32_t)fuses->anti_rollback_disable);
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_IDEVID_CERT_ATTR_0, fuses->idevid_cert_attr, sizeof(fuses->idevid_cert_attr));
    CALIPTRA_FUSE_ARRAY_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_IDEVID_MANUF_HSM_ID_0, fuses->idevid_manuf_hsm_id, sizeof(fuses->idevid_manuf_hsm_id));
    CALIPTRA_FUSE_WRITE(model, GENERIC_AND_FUSE_REG_FUSE_LIFE_CYCLE, (uint32_t)fuses->life_cycle);

    // Write to Caliptra Fuse Done
    caliptra_model_apb_write_u32(model, CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FUSE_WR_DONE, 1);

    // It shouldn`t be longer ready for fuses
    if (caliptra_model_ready_for_fuses(model))
        return -EIO;

    return 0;
}

int caliptra_bootfsm_go(struct caliptra_model *model)
{
    // Parameter check
    if (!model) {
        return -EINVAL;
    }

    // Write BOOTFSM_GO Register
    caliptra_model_apb_write_u32(model, CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_BOOTFSM_GO, 1);

    return 0;
}