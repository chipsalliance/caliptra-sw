// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "caliptra_types.h"
#include "caliptra_enums.h"
#include "caliptra_if.h"

#define ARRAY_SIZE(array) ((size_t)(sizeof(array) / sizeof(array[0])))

// Write into Caliptra BootFSM Go Register
int caliptra_bootfsm_go();

// Query if ROM is ready for firmware
bool caliptra_ready_for_firmware(void);

// Upload Caliptra Firmware
int caliptra_upload_fw(struct caliptra_buffer *fw_buffer);

// Read Caliptra FIPS Version
int caliptra_get_fips_version(struct caliptra_fips_version *version);

// Execute Mailbox Command
int caliptra_mailbox_execute(uint32_t cmd, struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer);
