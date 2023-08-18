// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "caliptra_enums.h"

typedef uint32_t caliptra_checksum;

/**
 * caliptra_buffer
 *
 * Transfer buffer for Caliptra mailbox commands
 */
#if !defined(HWMODEL)
typedef struct caliptra_buffer {
  const uint8_t *data; //< Pointer to a buffer with data to send/space to receive
  uintptr_t len;       //< Size of the buffer
} caliptra_buffer;
#endif

/**
 * caliptra_fuses
 *
 * Fuse data to be written to Caliptra registers
 */
struct caliptra_fuses {
    uint32_t uds_seed[12];
    uint32_t field_entropy[8];
    uint32_t key_manifest_pk_hash[12];
    uint32_t key_manifest_pk_hash_mask : 4;
    uint32_t rsvd : 28;
    uint32_t owner_pk_hash[12];
    uint32_t fmc_key_manifest_svn;
    uint32_t runtime_svn[4];
    bool anti_rollback_disable;
    uint32_t idevid_cert_attr[24];
    uint32_t idevid_manuf_hsm_id[4];
    enum device_lifecycle life_cycle;
};

struct caliptra_completion {
    caliptra_checksum checksum;
    enum fips_status fips;
};

struct caliptra_fips_version {
    struct caliptra_completion cpl;
    uint32_t mode;
    uint32_t fips_rev[3];
    uint8_t name[12];
};

struct caliptra_stash_measurement_req {
    caliptra_checksum checksum;
    uint8_t           metadata[4];
    uint8_t           measurement[48];
    uint32_t          svn;
};

struct caliptra_stash_measurement_resp {
    struct caliptra_completion cpl;
    uint32_t                   dpe_result;
};
