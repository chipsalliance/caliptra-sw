// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "caliptra_if.h"
#include "caliptra_types.h"

/**
 * DeviceLifecycle
 *
 * Device life cycle states
 */
enum DeviceLifecycle {
    Unprovisioned = 0,
    Manufacturing = 1,
    Reserved2 = 2,
    Production = 3,
};

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
    enum DeviceLifecycle life_cycle;
};



// Query if ROM is ready for fuses
bool caliptra_ready_for_fuses(void);

// Initialize Caliptra fuses prior to boot
int caliptra_init_fuses(struct caliptra_fuses *fuses);

// Write into Caliptra BootFSM Go Register
int caliptra_bootfsm_go();

/**
 * caliptra_ready_for_firmware
 *
 * Reports if the Caliptra hardware is ready for firmware upload
 *
 * @return bool True if ready, false otherwise
 */
bool caliptra_ready_for_firmware(void);

/**
 * caliptra_upload_fw
 *
 * Upload firmware to the Caliptra device
 *
 * @param[in] fw_buffer Buffer containing Caliptra firmware
 *
 * @return See caliptra_mailbox, mb_resultx_execute for possible results.
 */
int caliptra_upload_fw(struct caliptra_buffer *fw_buffer);

/**
 * caliptra_get_fips_version
 *
 * Read Caliptra FIPS Version
 *
 * @param[out] version pointer to fips_version unsigned integer
 *
 * @return See caliptra_mailbox_execute for possible results.
 */
int caliptra_get_fips_version(struct caliptra_fips_version *version);

// Retrieve the self-signed IDevID CSR
// This command is available in ROM ONLY.
int caliptra_get_idev_csr_rom(struct caliptra_buffer *buffer);

// Retrieve the self-signed LDevID certificate.
// This command is available in ROM ONLY.
int caliptra_get_ldev_csr_rom(struct caliptra_buffer *buffer);

/**
 * caliptra_stash_measurement
 *
 * Perform a measurement in to the DPE context.
 *
 * @param[in] req Data to be measured and stored.
 * @param[out] response DPE measurement result
 *
 * @return -EINVAL if the return checksum fails
 */
int caliptra_stash_measurement(struct stash_measurement_req *req, struct dpe_result *resp);
