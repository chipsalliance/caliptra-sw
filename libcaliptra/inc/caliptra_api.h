// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "caliptra_types.h"

#define CALIPTRA_ARRAY_SIZE(array) ((size_t)(sizeof(array) / sizeof(array[0])))

#ifdef __cplusplus
extern "C" {
#endif

// Write into Caliptra BootFSM Go Register
// returns: 0                       - Success
int caliptra_bootfsm_go();

// Set the WDT timeout value for caliptra
void caliptra_set_wdt_timeout(uint64_t timeout);

// Set the iTRNG entropy for caliptra
void caliptra_configure_itrng_entropy(uint16_t low_threshold, uint16_t high_threshold, uint16_t repetition_count);

// Sets the provided pauser value in one of the mbox_pauser_valid regs and sets the corresponding lock bit
// If all slots are locked, returns PAUSER_LOCKED error
int caliptra_mbox_pauser_set_and_lock(uint32_t pauser);

// Sets the provided pauser value in the fuse_pauser_valid reg and sets the lock bit
// Returns PAUSER_LOCKED error if already locked
int caliptra_fuse_pauser_set_and_lock(uint32_t pauser);

// Determine if Caliptra is ready to program fuses
bool caliptra_ready_for_fuses(void);

// Program calpitra_fuse object contents to caliptra fuses
// returns: 0                       - Success
//          INVALID_PARAMS          - Pointer to fuse struct is NULL
//          NOT_READY_FOR_FUSES     - Flow status does not indicate ready for fuses before initializing
//          STILL_READY_FOR_FUSES   - Flow status still indicates ready for fuses after writing fuse done
int caliptra_init_fuses(const struct caliptra_fuses *fuses);

// Query if ROM is ready for firmware
bool caliptra_ready_for_firmware(void);

// Read the value of the caliptra FW non-fatal error code
// returns: Caliptra error code (see error/src/lib.rs)
uint32_t caliptra_read_fw_non_fatal_error();

// Read the value of the caliptra FW fatal error code
// returns: Caliptra error code (see error/src/lib.rs)
uint32_t caliptra_read_fw_fatal_error();

// Generic write for a caliptra register
int caliptra_write_reg(uint32_t addr, uint32_t data);

// Generic read for a caliptra register
int caliptra_read_reg(uint32_t addr, uint32_t *data);

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
int caliptra_mailbox_execute(uint32_t cmd, const struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer, bool async);

// For full command details, please refer to the Caliptra Runtime Readme file at runtime\README.md

// Upload Caliptra Firmware
// Requires entire FW as fw_buffer
// For loading chunks of data at a time, use start/send/end functions below
int caliptra_upload_fw(const struct caliptra_buffer *fw_buffer, bool async);

// If the SoC cannot buffer the entire FW, the following 3 functions can be used to write chunks at a time
// Upload Caliptra Firmware Start Request
// Begin a FW_LOAD command to caliptra. Total FW size is needed at the start per mailbox protocol
int caliptra_upload_fw_start_req(uint32_t fw_size_in_bytes);

// Upload Caliptra Firmware Send Data
// Load a chunk of the FW data to Caliptra
// Intended to be called multiple times
// MUST follow caliptra_upload_fw_start_req and precede caliptra_upload_fw_end_request
// Size MUST be dword aligned for any chunks except the final chunk
int caliptra_upload_fw_send_data(const struct caliptra_buffer *fw_buffer);

// Upload Caliptra Firmware End Request
// End the FW_LOAD request after sending all the FW data
// Waits for Caliptra completion and response if async is false
int caliptra_upload_fw_end_req(bool async);

// Get IDEV cert
int caliptra_get_idev_cert(struct caliptra_get_idev_cert_req *req, struct caliptra_get_idev_cert_resp *resp, bool async);

// Get IDEV info
int caliptra_get_idev_info(struct caliptra_get_idev_info_resp *resp, bool async);

// Populate IDEV cert
int caliptra_populate_idev_cert(struct caliptra_populate_idev_cert_req *req, bool async);

// Get LDEV cert
int caliptra_get_ldev_cert(struct caliptra_get_ldev_cert_resp *resp, bool async);

// Get FMC Alias cert
int caliptra_get_fmc_alias_cert(struct caliptra_get_fmc_alias_cert_resp *resp, bool async);

// Get RT Alias cert
int caliptra_get_rt_alias_cert(struct caliptra_get_rt_alias_cert_resp *resp, bool async);

// ECDSA384 Verify
int caliptra_ecdsa384_verify(struct caliptra_ecdsa_verify_req *req, bool async);

// LMS Verify
int caliptra_lms_verify(struct caliptra_lms_verify_req *req, bool async);

// Stash measurement
int caliptra_stash_measurement(struct caliptra_stash_measurement_req *req, struct caliptra_stash_measurement_resp *resp, bool async);

// DPE command
int caliptra_invoke_dpe_command(struct caliptra_invoke_dpe_req *req, struct caliptra_invoke_dpe_resp *resp, bool async);

// Disable attestation
int caliptra_disable_attestation(bool async);

// FW Info
int caliptra_fw_info(struct caliptra_fw_info_resp *resp, bool async);

// DPE tag TCI
int caliptra_dpe_tag_tci(struct caliptra_dpe_tag_tci_req *req, bool async);

// DPE get tagged TCI
int caliptra_dpe_get_tagged_tci(struct caliptra_get_tagged_tci_req *req, struct caliptra_get_tagged_tci_resp *resp, bool async);

// Increment PCR Reset Counter
int caliptra_increment_pcr_reset_counter(struct caliptra_increment_pcr_reset_counter_req *req, bool async);

// Quote PCRs
int caliptra_quote_pcrs(struct caliptra_quote_pcrs_req *req, struct caliptra_quote_pcrs_resp *resp, bool async);

// Extend PCR
int caliptra_extend_pcr(struct caliptra_extend_pcr_req *req, bool async);

// Add subject alt name
int caliptra_add_subject_alt_name(struct caliptra_add_subject_alt_name_req *req, bool async);

// Certify key extended
int caliptra_certify_key_extended(struct caliptra_certify_key_extended_req *req, struct caliptra_certify_key_extended_resp *resp, bool async);

// FIPS version
int caliptra_fips_version(struct caliptra_fips_version_resp *resp, bool async);

// Get IDev CSR
int caliptra_get_idev_csr(struct caliptra_get_idev_csr_resp *resp, bool async);

// Self test start
int caliptra_self_test_start(bool async);

// Self test get results
int caliptra_self_test_get_results(bool async);

// Shutdown
int caliptra_shutdown(bool async);

// Capabilities
int caliptra_capabilities(struct caliptra_capabilities_resp *resp, bool async);

// Query if IDevID CSR is ready.
bool caliptra_is_idevid_csr_ready();

int caliptra_retrieve_idevid_csr(struct caliptra_buffer* caliptra_idevid_csr);

void caliptra_req_idev_csr_start();

// Clear IDEV CSR request.
void caliptra_req_idev_csr_complete();

#ifdef __cplusplus
}
#endif

