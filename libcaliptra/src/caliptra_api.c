// Licensed under the Apache-2.0 license
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <caliptra_top_reg.h>
#include "caliptra_enums.h"
#include "caliptra_if.h"
#include "caliptra_api.h"
#include "caliptra_types.h"
#include "caliptra_fuses.h"
#include "caliptra_mbox.h"

#define CALIPTRA_STATUS_NOT_READY (0)
#define CALIPTRA_REG_BASE (CALIPTRA_TOP_REG_MBOX_CSR_BASE_ADDR)
#define CALIPTRA_REG_LIMIT (CALIPTRA_REG_BASE + CALIPTRA_MAILBOX_MAX_SIZE - 1)

// User can define a data section for global vars if needed like #define CALIPTRA_API_GLOBAL_SECTION ".custom_section"
#ifdef CALIPTRA_API_GLOBAL_SECTION
#define CALIPTRA_API_GLOBAL_SECTION_ATTRIBUTE __attribute__((section(CALIPTRA_API_GLOBAL_SECTION)))
#else
#define CALIPTRA_API_GLOBAL_SECTION_ATTRIBUTE
#endif

// All globals should use CALIPTRA_API_GLOBAL_SECTION_ATTRIBUTE
// Globals should be uninitialized to maximize environment compatibility
static struct caliptra_buffer g_caliptra_mbox_pending_rx_buffer CALIPTRA_API_GLOBAL_SECTION_ATTRIBUTE;
static uint8_t g_caliptra_fw_load_piecewise_in_progress CALIPTRA_API_GLOBAL_SECTION_ATTRIBUTE;

#define CREATE_PARCEL(name, op, req, resp) \
    struct parcel name = { \
        .command   = op, \
        .tx_buffer = (uint8_t*)req, \
        .tx_bytes  = sizeof(*req), \
        .rx_buffer = (uint8_t*)resp, \
        .rx_bytes  = sizeof(*resp), \
    };

/**
 * caliptra_write_reg
 *
 * Write data to a caliptra reg at addr
 *
 * @param[in] address Address of the caliptra register
 * @param[in] data Data to write
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_write_reg(uint32_t address, uint32_t data)
{
    if (address < CALIPTRA_REG_BASE || address > CALIPTRA_REG_LIMIT) {
        return INVALID_PARAMS;
    }

    if (caliptra_write_u32(address, data)) {
        return REG_ACCESS_ERROR;
    }

    return 0;
}

/**
 * caliptra_read_reg
 *
 * Read to data from a caliptra reg at addr
 *
 * @param[in] address Address of the caliptra register
 * @param[out] data Data read
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_read_reg(uint32_t address, uint32_t *data)
{
    if (address < CALIPTRA_REG_BASE || address > CALIPTRA_REG_LIMIT) {
        return INVALID_PARAMS;
    }

    if (data == NULL) {
        return INVALID_PARAMS;
    }

    if (caliptra_read_u32(address, data)){
        return REG_ACCESS_ERROR;
    }

    return 0;
}

/**
 * calculate_caliptra_checksum
 *
 * This generates a checksum based on a sum of the command and the buffer, then
 * subtracted from zero.
 *
 * @param[in] cmd The command being sent to the caliptra device
 * @param[in] buffer A pointer, if applicable, to the buffer being sent
 * @param[in] len The size of the buffer
 *
 * @return Checksum value
 */
static uint32_t calculate_caliptra_checksum(uint32_t cmd, const uint8_t *buffer, uint32_t len)
{
    uint32_t i, sum = 0;

    if ((buffer == NULL) && (len != 0))
    {
        // Don't respect bad parameters
        return 0;
    }

    for (i = 0; i < sizeof(uint32_t); i++)
    {
        sum += ((uint8_t*)(&cmd))[i];
    }

    for (i = 0; i < len; i++)
    {
        sum += buffer[i];
    }

    return (0 - sum);
}

/**
 * caliptra_read_status
 *
 * HELPER - Reads the caliptra flow status register
 *
 * @return Status value
 */
static inline uint32_t caliptra_read_status(void)
{
    uint32_t status;

    caliptra_read_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS, &status);

    return status;
}

/**
 * caliptra_bootfsm_go
 *
 * Initiate caliptra hw startup
 *
 * @return 0 if successful
 */
int caliptra_bootfsm_go()
{
    // Write BOOTFSM_GO Register
    caliptra_write_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_BOOTFSM_GO, 1);

    // TODO: Check registers/provide async completion mechanism

    return 0;
}


/**
 * caliptra_set_wdt_timeout
 *
 * Write the provided WDT timeout value to CPTRA_WDT_CFG regs
 *
 * @param[in] timeout WDT timeout
 */
void caliptra_set_wdt_timeout(uint64_t timeout)
{
    caliptra_wdt_cfg_write(timeout);
}

/**
 * caliptra_configure_itrng_entropy
 *
 * Write the provided iTRNG config values to their respective regs
 *
 * @param[in] low_threshold iTRNG config value
 * @param[in] high_threshold iTRNG config value
 * @param[in] repetition_count iTRNG config value
 */
void caliptra_configure_itrng_entropy(uint16_t low_threshold, uint16_t high_threshold, uint16_t repetition_count)
{
    caliptra_write_itrng_entropy_low_threshold(low_threshold);
    caliptra_write_itrng_entropy_high_threshold(high_threshold);
    caliptra_write_itrng_entropy_repetition_count(repetition_count);
}

/**
 * caliptra_mbox_pauser_set_and_lock
 *
 * Sets the provided pauser value in one of the mbox_pauser_valid regs and set the
 * corresponding lock bit
 * If all slots are locked, returns PAUSER_LOCKED error
 *
 * @param[in] pauser pauser value to set for mbox_pauser_valid
 *
 * @return 0 for success, PAUSER_LOCKED if all slots are already locked
 */
int caliptra_mbox_pauser_set_and_lock(uint32_t pauser)
{
    for (int i = 0; i < MBOX_PAUSER_SLOTS; i++) {
        // Check if the slot is unlocked
        if (caliptra_read_mbox_pauser_lock(i) == 0) {
            caliptra_write_mbox_valid_pauser(i, pauser);
            caliptra_set_mbox_pauser_lock(i);
            return 0;
        }
    }

    return PAUSER_LOCKED;
}

/**
 * caliptra_fuse_pauser_set_and_lock
 *
 * Sets the provided pauser value in the fuse_pauser_valid reg and sets the lock bit
 * Returns PAUSER_LOCKED error if already locked
 *
 * @param[in] pauser pauser value to set for mbox_pauser_valid
 *
 * @return 0 for success, PAUSER_LOCKED if already locked
 */
int caliptra_fuse_pauser_set_and_lock(uint32_t pauser)
{
    // Check if the slot is unlocked
    if (caliptra_read_fuse_pauser_lock() == 0) {
        caliptra_write_fuse_valid_pauser(pauser);
        caliptra_set_fuse_pauser_lock();
        return 0;
    }

    return PAUSER_LOCKED;
}

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
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_init_fuses(const struct caliptra_fuses *fuses)
{
    // Parameter check
    if (!fuses)
    {
        return INVALID_PARAMS;
    }

    // Check whether caliptra is ready for fuses
    if (!caliptra_ready_for_fuses())
        return NOT_READY_FOR_FUSES;



    // Write Fuses
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_UDS_SEED_0, fuses->uds_seed, CALIPTRA_ARRAY_SIZE(fuses->uds_seed));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_FIELD_ENTROPY_0, fuses->field_entropy, CALIPTRA_ARRAY_SIZE(fuses->field_entropy));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_0, fuses->key_manifest_pk_hash, CALIPTRA_ARRAY_SIZE(fuses->key_manifest_pk_hash));
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_MASK, fuses->key_manifest_pk_hash_mask);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_OWNER_PK_HASH_0, fuses->owner_pk_hash, CALIPTRA_ARRAY_SIZE(fuses->owner_pk_hash));
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_FMC_KEY_MANIFEST_SVN, fuses->fmc_key_manifest_svn);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_RUNTIME_SVN_0, fuses->runtime_svn, CALIPTRA_ARRAY_SIZE(fuses->runtime_svn));
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_ANTI_ROLLBACK_DISABLE, (uint32_t)fuses->anti_rollback_disable);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_IDEVID_CERT_ATTR_0, fuses->idevid_cert_attr, CALIPTRA_ARRAY_SIZE(fuses->idevid_cert_attr));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_IDEVID_MANUF_HSM_ID_0, fuses->idevid_manuf_hsm_id, CALIPTRA_ARRAY_SIZE(fuses->idevid_manuf_hsm_id));
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_LIFE_CYCLE, (uint32_t)fuses->life_cycle);
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_LMS_VERIFY, (uint32_t)fuses->lms_verify);
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_LMS_REVOCATION, fuses->lms_revocation);
    caliptra_generic_and_fuse_write(GENERIC_AND_FUSE_REG_FUSE_SOC_STEPPING_ID, fuses->soc_stepping_id);

    // Write to Caliptra Fuse Done
    caliptra_write_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FUSE_WR_DONE, 1);

    // No longer ready for fuses
    if (caliptra_ready_for_fuses())
        return STILL_READY_FOR_FUSES;

    return 0;
}

/**
 * caliptra_read_fw_non_fatal_error
 *
 * Read value of the FW error non-fatal reg (see error/src/lib.rs)
 *
 * @return Caliptra FW Error code
 */
uint32_t caliptra_read_fw_non_fatal_error()
{
    return caliptra_read_fw_error_non_fatal();
}

/**
 * caliptra_read_fw_fatal_error
 *
 * Read value of the FW error fatal reg (see error/src/lib.rs)
 *
 * @return Caliptra FW Error code
 */
uint32_t caliptra_read_fw_fatal_error()
{
    return caliptra_read_fw_error_fatal();
}

/**
 * caliptra_ready_for_firmware
 *
 * Reports if the Caliptra hardware is ready for firmware upload
 *
 * @return bool True if ready, false otherwise
 */
bool caliptra_ready_for_firmware(void)
{
    uint32_t status;
    bool ready = false;

    do
    {
        status = caliptra_read_status();

        if ((status & GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_FW_MASK) == GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_FW_MASK)
        {
            ready = true;
        }
        else
        {
            caliptra_wait();
        }
    } while (ready == false);

    return true;
}

/*
* caliptra_is_csr_ready
*
* Reports if the IDEVID CSR is ready
*
* @return bool True if ready, false otherwise
*/
bool caliptra_is_csr_ready(void)
{
    uint32_t status;

    status = caliptra_read_status();

    if ((status & GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_IDEVID_CSR_READY_MASK) == GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_IDEVID_CSR_READY_MASK)
    {
        return true;
    }

    return false;
}


/**
 * caliptra_mailbox_write_fifo
 *
 * HELPER - Transfer contents of buffer into the mailbox FIFO
 *
 * @param[in] buffer Pointer to a valid caliptra_buffer struct
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
static int caliptra_mailbox_write_fifo(const struct caliptra_buffer *buffer)
{
    // Check if buffer is not null.
    if (buffer == NULL)
    {
        return INVALID_PARAMS;
    }

    // TODO: Should we enforce we don't exceed the previously written mbox_write_dlen value?

    if (buffer->len == 0)
    {
        // We can return early, there is no payload.
        return 0;
    }

    // We have data to write, better check if have a place to read it
    // from.
    if (buffer->data == NULL)
    {
        return INVALID_PARAMS;
    }

    uint32_t remaining_len = buffer->len;
    uint32_t *data_dw = (uint32_t *)buffer->data;

    // Copy DWord multiples
    while (remaining_len > sizeof(uint32_t))
    {
        caliptra_mbox_write(MBOX_CSR_MBOX_DATAIN, *data_dw++);
        remaining_len -= sizeof(uint32_t);
    }

    // if un-aligned dword remainder...
    if (remaining_len)
    {
        uint32_t data = 0;
        memcpy(&data, data_dw, remaining_len);
        caliptra_mbox_write(MBOX_CSR_MBOX_DATAIN, data);
    }

    return 0;
}

/**
 * caliptra_mailbox_read_fifo
 *
 * HELPER - Read a mailbox FIFO into a buffer
 *
 * @param[out] buffer A pointer to a valid caliptra_buffer struct
 * @param[out] bytes_read Pointer to dword to update with the number of bytes read (ignored if nullptr)
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
static int caliptra_mailbox_read_fifo(struct caliptra_buffer *buffer, uint32_t *bytes_read)
{
    uint32_t remaining_len = caliptra_mbox_read_dlen();

    // Check that the buffer is not null
    if (buffer == NULL) {
        return INVALID_PARAMS;
    }

    if (bytes_read) {
        *bytes_read = 0;
    }

    // Check we have enough room in the buffer
    if (buffer->len < remaining_len || !buffer->data) {
        return INVALID_PARAMS;
    }

    uint32_t *data_dw = (uint32_t *)buffer->data;

    // Copy DWord multiples
    while (remaining_len >= sizeof(uint32_t))
    {
        *data_dw++ = caliptra_mbox_read(MBOX_CSR_MBOX_DATAOUT);
        remaining_len -= sizeof(uint32_t);
        if (bytes_read) {
            *bytes_read += 4;
        }
    }

    // if un-aligned dword reminder...
    if (remaining_len)
    {
        uint32_t data = caliptra_mbox_read(MBOX_CSR_MBOX_DATAOUT);
        memcpy(data_dw, &data, remaining_len);
        if (bytes_read) {
            *bytes_read += remaining_len;
        }
    }
    return 0;
}

/**
 * caliptra_check_status_get_response
 *
 * HELPER - Checks the HW mailbox status for "complete" or "data ready" and populates the response
 * buffer with a response if applicable
 *
 * @param[out] mbox_rx_buffer Buffer for the response, NULL if no response is expected
 * @param[out] bytes_read Pointer to dword to update with the number of bytes read
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_check_status_get_response(struct caliptra_buffer *mbox_rx_buffer, uint32_t *bytes_read)
{
    // Only called internally, should always have a valid pointer
    if (bytes_read == NULL) {
        return API_INTERNAL_ERROR;
    }

    // Check the Mailbox Status
    uint32_t mbx_status = caliptra_mbox_read_status();
    if (mbx_status == CALIPTRA_MBOX_STATUS_CMD_FAILURE)
    {
        caliptra_mbox_write_execute(false);
        return MBX_STATUS_FAILED;
    }
    else if (mbx_status == CALIPTRA_MBOX_STATUS_CMD_COMPLETE)
    {
        caliptra_mbox_write_execute(false);
        return 0;
    }
    else if (mbx_status != CALIPTRA_MBOX_STATUS_DATA_READY)
    {
        return MBX_STATUS_UNKNOWN;
    }

    // Read Buffer
    int status = caliptra_mailbox_read_fifo(mbox_rx_buffer, bytes_read);

    // Execute False
    caliptra_mbox_write_execute(false);

    // Wait (HW model is halted whenever we aren't calling wait())
    caliptra_wait();

    if (caliptra_mbox_read_status_fsm() != CALIPTRA_MBOX_STATUS_FSM_IDLE)
        return MBX_STATUS_NOT_IDLE;

    return status;
}

/**
 * check_command_response
 *
 * HELPER - Verifies the checksum and checks that the FIPS status is approved for the message response
 *
 * @param[in] buffer Buffer for the full response
 * @param[in] response_size Size of the full response in bytes
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
static inline int check_command_response(const uint8_t *buffer, const size_t response_size)
{
    if (response_size < sizeof(struct caliptra_resp_header)) {
        return MBX_RESP_NO_HEADER;
    }
    struct caliptra_resp_header *resp_hdr = (struct caliptra_resp_header*)buffer;

    uint32_t calc_checksum = calculate_caliptra_checksum(0, buffer + sizeof(uint32_t), response_size - sizeof(uint32_t));

    bool checksum_valid = !(resp_hdr->chksum - calc_checksum);
    bool fips_approved  = (resp_hdr->fips_status == FIPS_STATUS_APPROVED);

    if (checksum_valid == false) {
        return MBX_RESP_CHKSUM_INVALID;
    }
    if (fips_approved == false) {
        return MBX_RESP_FIPS_NOT_APPROVED;
    }

    return 0;
}

/**
 * caliptra_mailbox_send_start
 *
 * HELPER - Send the message to caliptra
 *
 * @param[in] cmd Caliptra command opcode
 * @param[in] data_size Number of bytes to be sent in the request (does not include command)
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_mailbox_send_start(uint32_t cmd, uint32_t data_size)
{
    if (data_size > CALIPTRA_MAILBOX_MAX_SIZE)
    {
        return INVALID_PARAMS;
    }

    // Get mailbox lock, return error if already locked
    if (caliptra_mbox_is_lock())
    {
        return MBX_BUSY;
    }

    // Write Cmd
    caliptra_mbox_write_cmd(cmd);

    // Write DLEN to transition to the next state (needed even if it is zero)
    caliptra_mbox_write_dlen(data_size);

    return 0;
};

/**
 * caliptra_mailbox_send_data
 *
 * HELPER - Send the data portion of the message to caliptra
 *          Can be called multiple times
 *
 * @param[in] mbox_tx_buffer Transmit buffer
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_mailbox_send_data(const struct caliptra_buffer *mbox_tx_buffer)
{
    // Write Tx Buffer
    return caliptra_mailbox_write_fifo(mbox_tx_buffer);
};

/**
 * caliptra_mailbox_send_complete
 *
 * HELPER - Set execute to indicate Calipta should now process the message
 *          Set the rx_buffer for the pending message if applicable
 *          Wait for the result if async is true
 *
 * @param[out] mbox_rx_buffer caliptra_buffer struct containing the pointer and length of the receive buffer
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_mailbox_send_complete(struct caliptra_buffer *mbox_rx_buffer, bool async)
{
    // Store buffer info or init to zero
    if (mbox_rx_buffer != NULL) {
        g_caliptra_mbox_pending_rx_buffer = *mbox_rx_buffer;
    } else {
        g_caliptra_mbox_pending_rx_buffer = (struct caliptra_buffer){NULL, 0};
    }

    // Set Execute bit
    caliptra_mbox_write_execute(true);

    // Stop here if this is async (user will poll and complete)
    if (async) {
        return 0;
    }

    // Wait indefinitely for completion
    while (!caliptra_test_for_completion()){
        caliptra_wait();
    }

    return caliptra_complete();
};

/**
 * caliptra_mailbox_execute
 * Send the command. If async is false, wait for completion and call caliptra_complete to get result
 *
 * @param[in] cmd 32 bit command identifier to be sent to caliptra
 * @param[in] mbox_tx_buffer caliptra_buffer struct containing the pointer and length of the send buffer
 * @param[out] mbox_rx_buffer caliptra_buffer struct containing the pointer and length of the receive buffer
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_mailbox_execute(uint32_t cmd, const struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer, bool async)
{
    // Mailbox send start
    int status = caliptra_mailbox_send_start(cmd, mbox_tx_buffer->len);
    if (status) {
        return status;
    }

    // Mailbox send data
    status = caliptra_mailbox_send_data(mbox_tx_buffer);
    if (status) {
        return status;
    }

    // Mailbox send complete
    return caliptra_mailbox_send_complete(mbox_rx_buffer, async);
}

/**
 * pack_and_execute_command
 *
 * HELPER - Create the caliptra buffer structs and call caliptra_mailbox_send
 *
 * @param[in] parcel struct with tx and rx buffers for the transactions
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
static int pack_and_execute_command(struct parcel *parcel, bool async)
{
    if (parcel == NULL)
    {
        return INVALID_PARAMS;
    }

    // Parcels will always have, at a minimum:
    //  > 4 byte tx buffer, for the checksum
    //  > 8 byte rx buffer, for the checksum and FIPS status
    if (!parcel->tx_buffer || !parcel->rx_buffer)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_buffer tx_buf = {
        .data = parcel->tx_buffer,
        .len  = parcel->tx_bytes,
    };

    struct caliptra_buffer rx_buf = {
        .data = parcel->rx_buffer,
        .len  = parcel->rx_bytes,
    };

    // Calculate and populate the checksum field
    // Clear the checksum field before calculating
    *((caliptra_checksum*)tx_buf.data) = 0x0;
    *((caliptra_checksum*)tx_buf.data) = calculate_caliptra_checksum(parcel->command, tx_buf.data, tx_buf.len);

    return caliptra_mailbox_execute(parcel->command, &tx_buf, &rx_buf, async);
}

/**
 * caliptra_test_for_completion
 *
 * Checks if there is an active command being processed by caliptra FW
 *
 * @return True if no command is pending, false if a command is pending
 */
bool caliptra_test_for_completion()
{
    return !caliptra_mbox_is_busy();
}

/**
 * caliptra_complete
 *
 * Check result, read back the response to the rx_buffer originally provided if necessary
 * Complete transaction with mbx HW by clearing execute
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_complete()
{
    // Return an error if no message is pending (execute is not set)
    if (caliptra_mbox_read_execute() == 0) {
        return MBX_NO_MSG_PENDING;
    }

    // Make sure the request is complete
    if (!caliptra_test_for_completion()) {
        return MBX_BUSY;
    }

    // Store the buffer locally and clear the global var
    // The global should never be set when we don't have the mbx HW lock
    // (HW lock protects this from race conditions)
    struct caliptra_buffer rx_buffer = g_caliptra_mbox_pending_rx_buffer;
    g_caliptra_mbox_pending_rx_buffer = (struct caliptra_buffer){NULL, 0};

    // Complete the transaction and read back a response if applicable
    uint32_t bytes_read = 0;
    int status = caliptra_check_status_get_response(&rx_buffer, &bytes_read);

    if (status)
    {
        return status;
    }

    // Verify the header data from the response
    if (rx_buffer.data != NULL) {
        return check_command_response(rx_buffer.data, bytes_read);
    }

    return 0;
}

/**
 * caliptra_upload_fw_start_req
 *
 * Upload Caliptra Firmware Start Request.  Begin a FW_LOAD command to caliptra
 *
 * @param[in] fw_size_in_bytes Total size of the FW to be sent in bytes
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_upload_fw_start_req(uint32_t fw_size_in_bytes)
{
    // Mailbox send start
    int status = caliptra_mailbox_send_start(OP_CALIPTRA_FW_LOAD, fw_size_in_bytes);
    if (status) {
        return status;
    }

    // Cannot assume initialization value of globals
    // If HW lock was open, we can be sure nothing was pending
    // Otherwise, caliptra_mailbox_send_start will fail and we won't execute this
    g_caliptra_fw_load_piecewise_in_progress = 0x1;

    return status;
}

/**
 * caliptra_upload_fw_send_data
 *
 * Load a chunk of the FW data to Caliptra. Intended to be called multiple times
 * Must follow caliptra_upload_fw_start_req and precede caliptra_upload_fw_end_req
 *
 * @param[in] fw_buffer Buffer containing Caliptra firmware
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_upload_fw_send_data(const struct caliptra_buffer *fw_buffer)
{
    // Make sure we are in the middle of a FW load
    if (g_caliptra_fw_load_piecewise_in_progress != FW_LOAD_PIECEWISE_IN_PROGRESS) {
        return FW_LOAD_NOT_IN_PROGRESS;
    }

    // Mailbox send data
    return caliptra_mailbox_send_data(fw_buffer);
}
/**
 * caliptra_upload_fw_end_req
 *
 * End the FW_LOAD request after sending all the FW data
 *
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_upload_fw_end_req(bool async)
{
    // Make sure we are in the middle of a FW load
    if (g_caliptra_fw_load_piecewise_in_progress != FW_LOAD_PIECEWISE_IN_PROGRESS) {
        return FW_LOAD_NOT_IN_PROGRESS;
    }

    // Mailbox send complete
    int status = caliptra_mailbox_send_complete(NULL, async);

    g_caliptra_fw_load_piecewise_in_progress = FW_LOAD_PIECEWISE_IDLE;

    return status;
}

/**
 * caliptra_upload_fw
 *
 * Upload firmware to the Caliptra device. Requires entire FW as fw_buffer
 *
 * @param[in] fw_buffer Buffer containing Caliptra firmware
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */
int caliptra_upload_fw(const struct caliptra_buffer *fw_buffer, bool async)
{
    // Parameter check
    if (fw_buffer == NULL)
        return INVALID_PARAMS;

    return caliptra_mailbox_execute(OP_CALIPTRA_FW_LOAD, fw_buffer, NULL, async);
}

// Generic info for all command wrapper functions below
/**
 * caliptra_<command>
 *
 * Send the specified command to Caliptra and receive the response
 *
 * NOTE: Not all commands require request or response structs
 *
 * @param[in] req pointer to request struct
 * @param[out] resp pointer to response struct
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non-zero for failure (see enum libcaliptra_error)
 */

// Get IDEV cert
int caliptra_get_idev_cert(struct caliptra_get_idev_cert_req *req, struct caliptra_get_idev_cert_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    CREATE_PARCEL(p, OP_GET_IDEV_CERT, req, resp);

    return pack_and_execute_command(&p, async);
}

// Get IDEV info
int caliptra_get_idev_info(struct caliptra_get_idev_info_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_GET_IDEV_INFO, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// Populate IDEV cert
int caliptra_populate_idev_cert(struct caliptra_populate_idev_cert_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_POPULATE_IDEV_CERT, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Get LDEV cert
int caliptra_get_ldev_cert(struct caliptra_get_ldev_cert_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_GET_LDEV_CERT, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// Get FMC alias cert
int caliptra_get_fmc_alias_cert(struct caliptra_get_fmc_alias_cert_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_GET_FMC_ALIAS_CERT, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// Get RT alias cert
int caliptra_get_rt_alias_cert(struct caliptra_get_rt_alias_cert_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_GET_RT_ALIAS_CERT, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// ECDSA384 Verify
int caliptra_ecdsa384_verify(struct caliptra_ecdsa_verify_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_ECDSA384_VERIFY, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// LMS Verify
int caliptra_lms_verify(struct caliptra_lms_verify_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_LMS_VERIFY, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Stash measurement
int caliptra_stash_measurement(struct caliptra_stash_measurement_req *req, struct caliptra_stash_measurement_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    CREATE_PARCEL(p, OP_STASH_MEASUREMENT, req, resp);

    return pack_and_execute_command(&p, async);
}

// DPE command
int caliptra_invoke_dpe_command(struct caliptra_invoke_dpe_req *req, struct caliptra_invoke_dpe_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    // While it will likely cause no harm, there's no sense in writing more
    // to the FIFO than is absolutely required. This command can have a variable
    // data buffer.
    uint32_t actual_bytes = sizeof(caliptra_checksum) + sizeof(uint32_t) + req->data_size;

    struct parcel p = {
        .command   = OP_INVOKE_DPE_COMMAND,
        .tx_buffer = (uint8_t*)req,
        .tx_bytes  = actual_bytes,
        .rx_buffer = (uint8_t*)resp,
        .rx_bytes  = sizeof(*resp),
    };

    return pack_and_execute_command(&p, async);
}

// Disable attestation
int caliptra_disable_attestation(bool async)
{
    struct caliptra_resp_header resp_hdr = {};
    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_DISABLE_ATTESTATION, &checksum, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// FW Info
int caliptra_fw_info(struct caliptra_fw_info_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_FW_INFO, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// DPE tag TCI
int caliptra_dpe_tag_tci(struct caliptra_dpe_tag_tci_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_DPE_TAG_TCI, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// DPE get tagged TCI
int caliptra_dpe_get_tagged_tci(struct caliptra_get_tagged_tci_req *req, struct caliptra_get_tagged_tci_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    CREATE_PARCEL(p, OP_DPE_GET_TAGGED_TCI, req, resp);

    return pack_and_execute_command(&p, async);
}

// Increment PCR Reset Counter
int caliptra_increment_pcr_reset_counter(struct caliptra_increment_pcr_reset_counter_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_INCREMENT_PCR_RESET_COUNTER, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Quote PCRs
int caliptra_quote_pcrs(struct caliptra_quote_pcrs_req *req, struct caliptra_quote_pcrs_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    CREATE_PARCEL(p, OP_QUOTE_PCRS, req, resp);

    return pack_and_execute_command(&p, async);
}

// Extend PCR
int caliptra_extend_pcr(struct caliptra_extend_pcr_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_EXTEND_PCR, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Add subject alt name
int caliptra_add_subject_alt_name(struct caliptra_add_subject_alt_name_req *req, bool async)
{
    if (!req)
    {
        return INVALID_PARAMS;
    }

    struct caliptra_resp_header resp_hdr = {};

    CREATE_PARCEL(p, OP_ADD_SUBJECT_ALT_NAME, req, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Certify key extended
int caliptra_certify_key_extended(struct caliptra_certify_key_extended_req *req, struct caliptra_certify_key_extended_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    CREATE_PARCEL(p, OP_CERTIFY_KEY_EXTENDED, req, resp);

    return pack_and_execute_command(&p, async);
}

// FIPS version
int caliptra_fips_version(struct caliptra_fips_version_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_FIPS_VERSION, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// Get IDev CSR
int caliptra_get_idev_csr(struct caliptra_get_idev_csr_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_GET_IDEV_CSR, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

// Self test start
int caliptra_self_test_start(bool async)
{
    struct caliptra_resp_header resp_hdr = {};
    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_SELF_TEST_START, &checksum, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Self test get results
int caliptra_self_test_get_results(bool async)
{
    struct caliptra_resp_header resp_hdr = {};
    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_SELF_TEST_GET_RESULTS, &checksum, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Shutdown
int caliptra_shutdown(bool async)
{
    struct caliptra_resp_header resp_hdr = {};
    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_SHUTDOWN, &checksum, &resp_hdr);

    return pack_and_execute_command(&p, async);
}

// Capabilities
int caliptra_capabilities(struct caliptra_capabilities_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    CREATE_PARCEL(p, OP_CAPABILITIES, &checksum, resp);

    return pack_and_execute_command(&p, async);
}

int caliptra_retrieve_idevid_csr(struct caliptra_buffer* caliptra_idevid_csr)
{
    if (!caliptra_idevid_csr) {
        return INVALID_PARAMS;
    }

    if (!caliptra_is_idevid_csr_ready()) {
        return IDEV_CSR_NOT_READY;
    }

    return caliptra_mailbox_read_fifo(caliptra_idevid_csr, NULL);
}

void caliptra_req_idev_csr_start()
{
    uint32_t dbg_manuf_serv_req;

    caliptra_read_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_DBG_MANUF_SERVICE_REG, &dbg_manuf_serv_req);

    // Write to Caliptra Fuse Done
    caliptra_write_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_DBG_MANUF_SERVICE_REG, dbg_manuf_serv_req | 0x01);
}

void caliptra_req_idev_csr_complete()
{
    uint32_t dbg_manuf_serv_req;

    caliptra_read_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_DBG_MANUF_SERVICE_REG, &dbg_manuf_serv_req);

    // Write to Caliptra Fuse Done
    caliptra_write_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_DBG_MANUF_SERVICE_REG, dbg_manuf_serv_req & ~0x01);
}


// Check if IDEV CSR is ready.
bool caliptra_is_idevid_csr_ready() {
    uint32_t status;

    caliptra_read_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS, &status);

    if ((status & GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_IDEVID_CSR_READY_MASK) != 0) {
        return true;
    }

    return false;
}
