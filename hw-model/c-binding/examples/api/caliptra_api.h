// Licensed under the Apache-2.0 license
#ifndef CALIPTRA_API_H
#define CALIPTRA_API_H

#include <stdint.h>
#include "caliptra_model.h"

enum DeviceLifecycle {
    Unprovisioned = 0,
    Manufacturing = 1,
    Reserved2 = 2,
    Production = 3,
};

struct caliptra_fuses {
    uint32_t uds_seed[12];
    uint32_t field_entropy[8];
    uint32_t vendor_pk_hash[12];
    uint32_t ecc_revocation : 4;
    uint32_t rsvd : 28;
    uint32_t owner_pk_hash[12];
    uint32_t firmware_svn[4];
    bool anti_rollback_disable;
    uint32_t idevid_cert_attr[24];
    uint32_t idevid_manuf_hsm_id[4];
    enum DeviceLifecycle life_cycle;
};

#ifdef __cplusplus
extern "C" {
#endif

// Initialize Caliptra fuses prior to boot
int caliptra_init_fuses(struct caliptra_model *model, struct caliptra_fuses *fuses);

// Write into Caliptra BootFSM Go Register
int caliptra_bootfsm_go(struct caliptra_model *model);

// Upload Caliptra Firmware
int caliptra_upload_fw(struct caliptra_model *model, struct caliptra_buffer *fw_buffer);

// Execute Mailbox Command
int caliptra_mailbox_execute(struct caliptra_model *model, uint32_t cmd, struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer);

#ifdef __cplusplus
}
#endif

#endif // CALIPTRA_API_H