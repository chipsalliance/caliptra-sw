// Licensed under the Apache-2.0 license
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <caliptra_top_reg.h>
#include "caliptra_if.h"
#include "caliptra_api.h"
#include "caliptra_fuses.h"
#include "caliptra_mbox.h"
#include "caliptra_enums.h"

#define CALIPTRA_STATUS_NOT_READY 0

struct caliptra_buffer g_mbox_pending_rx_buffer = {NULL, 0};

/**
 * calculate_caliptra_checksum
 *
 * HELPER - This generates a checksum based on a sum of the command and the buffer, then
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
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_init_fuses(struct caliptra_fuses *fuses)
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
    bool ready;

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

/**
 * caliptra_mailbox_write_fifo
 *
 * HELPER - Transfer contents of buffer into the mailbox FIFO
 *
 * @param[in] buffer Pointer to a valid caliptra_buffer struct
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
static int caliptra_mailbox_write_fifo(struct caliptra_buffer *buffer)
{
    // Check if buffer is not null.
    if (buffer == NULL)
    {
        return INVALID_PARAMS;
    }

    if (buffer->len > CALIPTRA_MAILBOX_MAX_SIZE)
    {
        return INVALID_PARAMS;
    }

    // Write DLEN to transition to the next state.
    caliptra_mbox_write_dlen(buffer->len);

    if (buffer->len == 0)
    {
        // We can return early, there is no payload.
        // dlen needs to be written to transition the state machine,
        // even if it is zero.
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
 * @param[in] buffer A pointer to a valid caliptra_buffer struct
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
static int caliptra_mailbox_read_fifo(struct caliptra_buffer *buffer)
{
    uint32_t remaining_len = caliptra_mbox_read_dlen();

    // Check that the buffer is not null
    if (buffer == NULL)
        return INVALID_PARAMS;

    // Check we have enough room in the buffer
    if (buffer->len < remaining_len || !buffer->data)
        return INVALID_PARAMS;

    uint32_t *data_dw = (uint32_t *)buffer->data;

    // Copy DWord multiples
    while (remaining_len >= sizeof(uint32_t))
    {
        *data_dw++ = caliptra_mbox_read(MBOX_CSR_MBOX_DATAOUT);
        remaining_len -= sizeof(uint32_t);
    }

    // if un-aligned dword reminder...
    if (remaining_len)
    {
        uint32_t data = caliptra_mbox_read(MBOX_CSR_MBOX_DATAOUT);
        memcpy(data_dw, &data, remaining_len);
    }
    return 0;
}

/**
 * caliptra_mailbox_send
 *
 * HELPER - Send the message to caliptra
 *
 * @param[in] cmd Caliptra command opcode
 * @param[in] mbox_tx_buffer Transmit buffer
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_mailbox_send(uint32_t cmd, struct caliptra_buffer *mbox_tx_buffer)
{
    // If mbox already locked return
    if (caliptra_mbox_is_lock())
    {
        return MBX_BUSY;
    }

    // Write Cmd and Tx Buffer
    caliptra_mbox_write_cmd(cmd);
    caliptra_mailbox_write_fifo(mbox_tx_buffer);

    // Set Execute bit
    caliptra_mbox_write_execute(true);

    return 0;
};

/**
 * caliptra_check_status_get_response
 *
 * HELPER - Checks the HW mailbox status for "complete" or "data ready" and populates the response
 * buffer with a response if applicable
 *
 * @param[in] mbox_rx_buffer Buffer for the response, NULL if no response is expected
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_check_status_get_response(struct caliptra_buffer *mbox_rx_buffer)
{
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
    int status = caliptra_mailbox_read_fifo(mbox_rx_buffer);

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
 * HELPER - Verfies the checksum and checks that the FIPS status is approved for the message response
 *
 * @param[in] buffer Buffer for the full response
 * @param[in] buffer_size Size of the full response in bytes
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
static inline int check_command_response(const uint8_t *buffer, const size_t buffer_size)
{
    if (buffer_size < sizeof(struct caliptra_completion)) {
        return MBX_RESP_NO_HEADER;
    }
    struct caliptra_completion *cpl = (struct caliptra_completion*)buffer;

    uint32_t calc_checksum = calculate_caliptra_checksum(0, buffer + sizeof(uint32_t), buffer_size - sizeof(uint32_t));

    bool checksum_valid = !(cpl->checksum - calc_checksum);
    bool fips_approved  = (cpl->fips == FIPS_STATUS_APPROVED);

    if (checksum_valid == false) {
        return MBX_RESP_CHKSUM_INVALID;
    }
    if (fips_approved == false) {
        return MBX_RESP_FIPS_NOT_APPROVED;
    }

    return 0;
}

/**
 * caliptra_mailbox_execute
 *
 * Send the command with caliptra_mailbox_send. If async is false, wait for completion and call caliptra_complete to get result
 *
 * @param[in] cmd 32 bit command identifier to be sent to caliptra
 * @param[in] mbox_tx_buffer caliptra_buffer struct containing the pointer and length of the send buffer
 * @param[in] mbox_rx_buffer caliptra_buffer struct containing the pointer and length of the receive buffer
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_mailbox_execute(uint32_t cmd, struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer, bool async)
{
    *((caliptra_checksum*)mbox_tx_buffer->data) = calculate_caliptra_checksum(cmd, mbox_tx_buffer->data, mbox_tx_buffer->len);

    int status = caliptra_mailbox_send(cmd, mbox_tx_buffer);
    if (status) {
        return status;
    }

    // HW lock should prevent this from happening
    if (g_mbox_pending_rx_buffer.data != NULL) {
        return API_INTERNAL_ERROR;
    }

    // Store buffer reference
    g_mbox_pending_rx_buffer = *mbox_rx_buffer;

    // Stop here if this is async (user will poll and complete)
    if (async) {
        return status;
    }

    // Wait indefinitely for completion
    while (!caliptra_test_for_completion()){
        caliptra_wait();
    }

    return caliptra_complete();
}

/**
 * pack_and_execute_command
 *
 * HELPER - Create the caliptra buffer structs and call caliptra_mailbox_execute
 *
 * @param[in] parcel struct with tx and rx buffers for the transcations
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
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
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
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
    struct caliptra_buffer rx_buffer = g_mbox_pending_rx_buffer;
    g_mbox_pending_rx_buffer = (struct caliptra_buffer){NULL, 0};

    // Complete the transaction and read back a response if applicable
    int status = caliptra_check_status_get_response(&rx_buffer);

    if (status)
    {
        return status;
    }

    // Verify the header data from the response
    if (rx_buffer.data != NULL) {
        return check_command_response(rx_buffer.data, rx_buffer.len);
    }
}

/**
 * caliptra_upload_fw
 *
 * Upload firmware to the Caliptra device
 *
 * @param[in] fw_buffer Buffer containing Caliptra firmware
 *
 * @return See caliptra_mailbox, mb_resultx_execute for possible results.
 */
int caliptra_upload_fw(struct caliptra_buffer *fw_buffer, bool async)
{
    // Parameter check
    if (fw_buffer == NULL)
        return INVALID_PARAMS;

    int status = caliptra_mailbox_send(OP_CALIPTRA_FW_LOAD, fw_buffer);

    // Stop here for async or if there is a failure
    if (status || async) {
        return status;
    }

    // Wait indefinitely for completion
    while (!caliptra_test_for_completion()){
        caliptra_wait();
    }

    return caliptra_complete();
}

/**
 * caliptra_get_fips_version
 *
 * Read Caliptra FIPS Version
 *
 * @param[out] version pointer to fips_version command response
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_get_fips_version(struct caliptra_fips_version *version, bool async)
{
    // Parameter check
    if (version == NULL)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    struct parcel p = {
        .command   = OP_FIPS_VERSION,
        .tx_buffer = (uint8_t*)&checksum,
        .tx_bytes  = sizeof(caliptra_checksum),
        .rx_buffer = (uint8_t*)version,
        .rx_bytes  = sizeof(struct caliptra_fips_version),
    };

    return pack_and_execute_command(&p, async);
}

/**
 * caliptra_stash_measurement
 *
 * Stash a measurement with Caliptra
 *
 * @param[out] req pointer to request struct
 * @param[out] resp pointer to response struct
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_stash_measurement(struct caliptra_stash_measurement_req *req, struct caliptra_stash_measurement_resp *resp, bool async)
{
    if (!req || !resp)
    {
        return INVALID_PARAMS;
    }

    struct parcel p = {
        .command   = OP_STASH_MEASUREMENT,
        .tx_buffer = (uint8_t*)req,
        .tx_bytes  = sizeof(struct caliptra_stash_measurement_req),
        .rx_buffer = (uint8_t*)resp,
        .rx_bytes  = sizeof(struct caliptra_stash_measurement_resp),
    };

    return pack_and_execute_command(&p, async);
}

/**
 * caliptra_get_idev_csr
 *
 * Get the IDEV certificate signing request
 *
 * @param[out] resp pointer to response struct
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_get_idev_csr(struct caliptra_get_idev_csr_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    struct parcel p = {
        .command   = OP_GET_IDEV_CSR,
        .tx_buffer = (uint8_t*)&checksum,
        .tx_bytes  = sizeof(caliptra_checksum),
        .rx_buffer = (uint8_t*)resp,
        .rx_bytes  = sizeof(struct caliptra_get_idev_csr_resp),
    };

    return pack_and_execute_command(&p, async);
}

/**
 * caliptra_get_ldev_cert
 *
 * Get the LDEV certificate
 *
 * @param[out] resp pointer to response struct
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_get_ldev_cert(struct caliptra_get_ldev_cert_resp *resp, bool async)
{
    if (!resp)
    {
        return INVALID_PARAMS;
    }

    caliptra_checksum checksum = 0;

    struct parcel p = {
        .command   = OP_GET_LDEV_CERT,
        .tx_buffer = (uint8_t*)&checksum,
        .tx_bytes  = sizeof(caliptra_checksum),
        .rx_buffer = (uint8_t*)resp,
        .rx_bytes  = sizeof(struct caliptra_get_ldev_cert_resp),
    };

    return pack_and_execute_command(&p, async);
}

/**
 * caliptra_dpe_command
 *
 * Send a DPE command and receive its response
 *
 * @param[out] req pointer to request struct
 * @param[out] resp pointer to response struct
 * @param[in] async If true, return after sending command. If false, wait for command to complete and handle response
 *
 * @return 0 for success, non zero for failure (see enum libcaliptra_error)
 */
int caliptra_dpe_command(struct caliptra_dpe_req *req, struct caliptra_dpe_resp *resp, bool async)
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
        .rx_bytes  = sizeof(struct caliptra_dpe_resp),
    };

    return pack_and_execute_command(&p, async);
}

