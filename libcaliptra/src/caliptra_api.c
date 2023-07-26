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

#define CALIPTRA_STATUS_NOT_READY 0

static inline uint32_t caliptra_read_status(void)
{
    uint32_t status;

    caliptra_read_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS, &status);

    return status;
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
    if ((caliptra_read_status() & GENERIC_AND_FUSE_REG_CPTRA_FLOW_STATUS_READY_FOR_FUSES_MASK) != 0) {
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
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_UDS_SEED_0, fuses->uds_seed, sizeof(fuses->uds_seed));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_FIELD_ENTROPY_0, fuses->field_entropy, sizeof(fuses->field_entropy));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_0, fuses->key_manifest_pk_hash, sizeof(fuses->key_manifest_pk_hash));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_KEY_MANIFEST_PK_HASH_MASK, fuses->key_manifest_pk_hash_mask);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_OWNER_PK_HASH_0, fuses->owner_pk_hash, sizeof(fuses->owner_pk_hash));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_FMC_KEY_MANIFEST_SVN, fuses->fmc_key_manifest_svn);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_FMC_KEY_MANIFEST_SVN, fuses->runtime_svn, sizeof(fuses->runtime_svn)); // https://github.com/chipsalliance/caliptra-sw/issues/529
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_ANTI_ROLLBACK_DISABLE, (uint32_t)fuses->anti_rollback_disable);
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_IDEVID_CERT_ATTR_0, fuses->idevid_cert_attr, sizeof(fuses->idevid_cert_attr));
    caliptra_fuse_array_write(GENERIC_AND_FUSE_REG_FUSE_IDEVID_MANUF_HSM_ID_0, fuses->idevid_manuf_hsm_id, sizeof(fuses->idevid_manuf_hsm_id));
    caliptra_fuse_write(GENERIC_AND_FUSE_REG_FUSE_LIFE_CYCLE, (uint32_t)fuses->life_cycle);

    // Write to Caliptra Fuse Done
    caliptra_write_u32(CALIPTRA_TOP_REG_GENERIC_AND_FUSE_REG_CPTRA_FUSE_WR_DONE, 1);

    // No longer ready for fuses
    if (caliptra_ready_for_fuses())
        return -EIO;

    return 0;
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
 * caliptra_mailbox_write_fifo
 *
 * Transfer contents of buffer into the mailbox FIFO
 *
 * @param[in] buffer Pointer to a valid caliptra_buffer struct
 *
 * @return int -EINVAL if the buffer is too large.
 */
static int caliptra_mailbox_write_fifo(struct caliptra_buffer *buffer)
{
    // Check against max size
    const uint32_t MBOX_SIZE = (128u * 1024u);

    // Check if buffer is not null.
    if (buffer == NULL)
    {
        return -EINVAL;
    }

    if (buffer->len > MBOX_SIZE)
    {
        return -EINVAL;
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
        return -EINVAL;
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
 * caliptra_mailbox_read_buffer
 *
 * Read a mailbxo FIFO into a buffer
 *
 * @param[in] buffer A pointer to a valid caliptra_buffer struct
 *
 * @return int 0 if successful, -EINVAL if the buffer is too small or the buffer pointer is invalid.
 */
static int caliptra_mailbox_read_buffer(struct caliptra_buffer *buffer)
{
    uint32_t remaining_len = caliptra_mbox_read_dlen();

    // Check that the buffer is not null
    if (buffer == NULL)
        return -EINVAL;

    // Check we have enough room in the buffer
    if (buffer->len < remaining_len || !buffer->data)
        return -EINVAL;

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
 * caliptra_mailbox_execute
 *
 * Execute a mailbox command and send/retrieve a buffer
 *
 * @param[in] cmd Caliptra command opcode
 * @param[in] mbox_tx_buffer Transmit buffer
 * @param[in] mbox_rx_buffer Receive buffer
 *
 * @return 0 if successful, -EBUSY if the mailbox is locked, -EIO if the command has failed or data is not available or the FSM is not include
 */
int caliptra_mailbox_execute(uint32_t cmd, struct caliptra_buffer *mbox_tx_buffer, struct caliptra_buffer *mbox_rx_buffer)
{
    // If mbox already locked return
    if (caliptra_mbox_is_lock())
    {
        return -EBUSY;
    }

    // Write Cmd and Tx Buffer
    caliptra_mbox_write_cmd(cmd);
    caliptra_mailbox_write_fifo(mbox_tx_buffer);

    // Set Execute bit and wait
    caliptra_mbox_write_execute_busy_wait(true);

    // Check the Mailbox Status
    uint32_t status = caliptra_mbox_read_status();
    if (status == CALIPTRA_MBOX_STATUS_CMD_FAILURE)
    {
        caliptra_mbox_write_execute(false);
        return -EIO;
    }
    else if (status == CALIPTRA_MBOX_STATUS_CMD_COMPLETE)
    {
        caliptra_mbox_write_execute(false);
        return 0;
    }
    else if (status != CALIPTRA_MBOX_STATUS_DATA_READY)
    {
        return -EIO;
    }

    // Read Buffer
    caliptra_mailbox_read_buffer(mbox_rx_buffer);

    // Execute False
    caliptra_mbox_write_execute(false);

    // Wait
    caliptra_wait();

    if (caliptra_mbox_read_status_fsm() != CALIPTRA_MBOX_STATUS_FSM_IDLE)
        return -EIO;

    return 0;
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
 * caliptra_upload_fw
 *
 * Upload firmware to the Caliptra device
 *
 * @param[in] fw_buffer Buffer containing Caliptra firmware
 *
 * @return See caliptra_mailbox, mb_resultx_execute for possible results.
 */
int caliptra_upload_fw(struct caliptra_buffer *fw_buffer)
{
    // Parameter check
    if (fw_buffer == NULL)
        return -EINVAL;

    const uint32_t FW_LOAD_CMD_OPCODE = 0x46574C44u;
    return caliptra_mailbox_execute(FW_LOAD_CMD_OPCODE, fw_buffer, NULL);
}

/**
 * caliptra_get_fips_version
 *
 * Read Caliptra FIPS Version
 *
 * @param[out] version pointer to fips_version unsigned integer
 *
 * @return See caliptra_mailbox, mb_resultx_execute for possible results.
 */
int caliptra_get_fips_version(struct caliptra_fips_version *version)
{
    // Parameter check
    if (version == NULL)
        return -EINVAL;

    uint32_t FIPS_VERSION_OPCODE = 0x46505652;

    struct caliptra_buffer in_buf = {
        .data = NULL,
        .len = 0,
    };
    struct caliptra_buffer out_buf = {
        .data = (uint8_t *)version,
        .len = sizeof(struct caliptra_fips_version),
    };

    return caliptra_mailbox_execute(FIPS_VERSION_OPCODE, &in_buf, &out_buf);
}
