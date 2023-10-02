// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "caliptra_types.h"
#include "caliptra_enums.h"
#include "caliptra_if.h"

#define ARRAY_SIZE(array) ((size_t)(sizeof(array) / sizeof(array[0])))

// Write into Caliptra BootFSM Go Register
// returns: 0                       - Success
int caliptra_bootfsm_go();

// Determine if Caliptra is ready to program fuses
bool caliptra_ready_for_fuses(void);

// Program calpitra_fuse object contents to caliptra fuses
// returns: 0                       - Success
//          INVALID_PARAMS          - Pointer to fuse struct is NULL
//          NOT_READY_FOR_FUSES     - Flow status does not indicate ready for fuses before initializing
//          STILL_READY_FOR_FUSES   - Flow status still indicates ready for fuses after writing fuse done
int caliptra_init_fuses(struct caliptra_fuses *fuses);

// Query if ROM is ready for firmware
bool caliptra_ready_for_firmware(void);

// Read the value of the caliptra FW non-fatal error code
// returns: Caliptra error code (see error/src/lib.rs)
uint32_t caliptra_read_fw_non_fatal_error();

// Read the value of the caliptra FW fatal error code
// returns: Caliptra error code (see error/src/lib.rs)
uint32_t caliptra_read_fw_fatal_error();

// MAILBOX COMMANDS
// Asynchronous operation:
//  - All commands have an option for asynchronous usage as their last param
//  - Setting this will cause the command function to return once the request has been issued to caliptra
//  - The caller should then poll for completion using caliptra_test_for_completion
//  - After successfully polling, the caller should use caliptra_complete to finish the transaction
//    and populate the response buffer originally provided.
//  - The caller MUST ensure the response buffer provided remains available until caliptra_complete returns

// Mailbox error codes
// returns: 0                           - Success
//          MBX_BUSY                    - Mailbox is still busy when trying to send, the previous operation was never completed
//          INVALID_PARAMS              - Params provided were null when not accepted or otherwise invalid
//          MBX_COMPLETE_NOT_READY      - Mailbox is still busy (poll on caliptra_test_for_completion before calling)
//          MBX_NO_MSG_PENDING          - No mailbox request has been issued
//          MBX_STATUS_FAILED           - Mailbox HW status was set to CMD_FAILURE by caliptra FW
//          MBX_STATUS_UNKNOWN          - Mailbox HW status is not a known/expected value
//          MBX_STATUS_NOT_IDLE         - Mailbox status did not return to idle after clearing execute
//          MBX_RESP_NO_HEADER          - The response buffer is too small to contain a header
//          MBX_RESP_CHKSUM_INVALID     - The checksum in the response is not valid
//          MBX_RESP_FIPS_NOT_APPROVED  - FIPS status in the response was not "approved"
//          API_INTERNAL_ERROR          - The API internal state no longer matches the HW state (should not be possible)

// Test for completion of the previously issued mailbox command
// returns: True   - Mailbox status is not busy
//          False  - Mailbox status shows busy
bool caliptra_test_for_completion();

// Resets the mailbox and SW state
// Populates the response buffer provided when issuing the command if applicable
// (See note above on return codes)
int caliptra_complete();

// Execute Mailbox Command
// Generic function for sending and receiving a command with raw, user-defined command and buffers
// NOT RECOMMENDED to be used directly when avoidable - use the functions below for the specific command
// (See notes above on asynchronous operation and return codes)
int caliptra_mailbox_execute(uint32_t cmd, struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer, bool async);

// Upload Caliptra Firmware
// (See notes above on asynchronous operation and return codes)
int caliptra_upload_fw(struct caliptra_buffer *fw_buffer, bool async);

// Read Caliptra FIPS Version
// (See notes above on asynchronous operation and return codes)
int caliptra_get_fips_version(struct caliptra_fips_version *version, bool async);

// Stash Measurement command
// (See notes above on asynchronous operation and return codes)
int caliptra_stash_measurement(struct caliptra_stash_measurement_req *req, struct caliptra_stash_measurement_resp *resp, bool async);

// Get IDEV CSR
// (See notes above on asynchronous operation and return codes)
int caliptra_get_idev_csr(struct caliptra_get_idev_csr_resp *resp, bool async);

// Get LDEV Cert
// (See notes above on asynchronous operation and return codes)
int caliptra_get_ldev_cert(struct caliptra_get_ldev_cert_resp *resp, bool async);


