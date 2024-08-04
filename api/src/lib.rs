// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]

mod capabilities;

mod checksum;

pub mod mailbox;

pub use caliptra_error as error;

pub use capabilities::Capabilities;

pub use checksum::{calc_checksum, verify_checksum};

use mailbox::CommandId;
pub use mailbox::{mbox_read_fifo, mbox_write_fifo};

use ureg::MmioMut;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaliptraApiError {
    MailboxCmdFailed(u32),
    UnableToLockMailbox,
    BufferTooLargeForMailbox,
    UploadFirmwareUnexpectedResponse,
    UnknownCommandStatus(u32),
    NotReadyForFwErr,
    ReadyForFirmwareTimeout {
        cycles: u32,
    },
    ProvidedIccmTooLarge,
    ProvidedDccmTooLarge,
    UnexpectedMailboxFsmStatus {
        expected: u32,
        actual: u32,
    },
    UnableToLockSha512Acc,
    UploadMeasurementResponseError,
    UnableToReadMailbox,
    MailboxNoResponseData,
    MailboxReqTypeTooSmall,
    MailboxRespTypeTooSmall,
    MailboxUnexpectedResponse,
    MailboxUnexpectedResponseLen {
        expected_min: u32,
        expected_max: u32,
        actual: u32,
    },
    MailboxRespInvalidChecksum {
        expected: u32,
        actual: u32,
    },
    MailboxRespInvalidFipsStatus(u32),
    MailboxTimeout,
    FusesAlreadyLocked,
}

pub trait Soc {
    type TMmio<'a>: MmioMut
    where
        Self: 'a;

    const CMD_TIMEOUT_CYCLES: u64;

    /// Returns a properily initalized  `RegisterBlock` that can be used to manipulate the Soc interface.    
    fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<Self::TMmio<'_>>;

    /// Returns a properily initalized  `RegisterBlock` that can be used to manipulate the mailbox
    fn mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<Self::TMmio<'_>>;

    /// Returns a properily initalized  `RegisterBlock` that can be used to manipulate the sha512_acc peripheral
    fn soc_sha512_acc(&mut self) -> caliptra_registers::sha512_acc::RegisterBlock<Self::TMmio<'_>>;

    /// A register block that can be used to manipulate the soc_ifc peripheral TRNG registers
    fn soc_ifc_trng(&mut self) -> caliptra_registers::soc_ifc_trng::RegisterBlock<Self::TMmio<'_>>;

    /// Initializes the fuse values and locks them in until the next reset. This
    /// function can only be called during early boot, shortly after the model
    /// is created with `new_unbooted()`.
    ///
    /// # Panics
    ///
    /// If the cptra_fuse_wr_done has already been written, or the
    /// hardware prevents cptra_fuse_wr_done from being set.
    fn init_fuses(
        &mut self,
        fuses: &caliptra_api_types::Fuses,
    ) -> core::result::Result<(), CaliptraApiError> {
        if !self.soc_ifc().cptra_reset_reason().read().warm_reset()
            && !self.soc_ifc().cptra_fuse_wr_done().read().done()
        {
            return Err(CaliptraApiError::FusesAlreadyLocked);
        }

        self.soc_ifc().fuse_uds_seed().write(&fuses.uds_seed);
        self.soc_ifc()
            .fuse_field_entropy()
            .write(&fuses.field_entropy);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash()
            .write(&fuses.key_manifest_pk_hash);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash_mask()
            .write(|w| w.mask(fuses.key_manifest_pk_hash_mask.into()));
        self.soc_ifc()
            .fuse_owner_pk_hash()
            .write(&fuses.owner_pk_hash);
        self.soc_ifc()
            .fuse_fmc_key_manifest_svn()
            .write(|_| fuses.fmc_key_manifest_svn);
        self.soc_ifc().fuse_runtime_svn().write(&fuses.runtime_svn);
        self.soc_ifc()
            .fuse_anti_rollback_disable()
            .write(|w| w.dis(fuses.anti_rollback_disable));
        self.soc_ifc()
            .fuse_idevid_cert_attr()
            .write(&fuses.idevid_cert_attr);
        self.soc_ifc()
            .fuse_idevid_manuf_hsm_id()
            .write(&fuses.idevid_manuf_hsm_id);
        self.soc_ifc()
            .fuse_life_cycle()
            .write(|w| w.life_cycle(fuses.life_cycle.into()));
        self.soc_ifc()
            .fuse_lms_verify()
            .write(|w| w.lms_verify(fuses.lms_verify));
        self.soc_ifc()
            .fuse_lms_revocation()
            .write(|_| fuses.fuse_lms_revocation);
        self.soc_ifc()
            .fuse_soc_stepping_id()
            .write(|w| w.soc_stepping_id(fuses.soc_stepping_id.into()));

        self.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        Ok(())
    }

    /// Upload firmware to the mailbox.
    fn upload_firmware(&mut self, firmware: &[u8]) -> Result<(), CaliptraApiError> {
        let resp_buf = &mut [];
        self.mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), firmware, resp_buf)
    }

    /// Executes `cmd` with request data `buf`. Returns `Ok(Some(_))` if
    /// the uC responded with data, `Ok(None)` if the uC indicated success
    /// without data, Err(ModelError::MailboxCmdFailed) if the microcontroller
    /// responded with an error, or other model errors if there was a problem
    /// communicating with the mailbox.
    fn mailbox_execute(
        &mut self,

        cmd: u32,

        req_buf: &[u8],

        resp_buf: &mut [u8],
    ) -> core::result::Result<(), CaliptraApiError> {
        self.start_mailbox_execute(cmd, req_buf)?;

        self.finish_mailbox_execute(resp_buf)
    }

    /// Send a command to the mailbox but don't wait for the response
    fn start_mailbox_execute(
        &mut self,

        cmd: u32,

        buf: &[u8],
    ) -> core::result::Result<(), CaliptraApiError> {
        // Read a 0 to get the lock

        if self.mbox().lock().read().lock() {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }

        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the PAUSER check or some other issue
        if !(self.mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToReadMailbox);
        }

        self.mbox().cmd().write(|_| cmd);

        mbox_write_fifo(&self.mbox(), buf)?;

        // Ask the microcontroller to execute this command

        self.mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

    /// Wait for the response to a previous call to `start_mailbox_execute()`.
    fn finish_mailbox_execute(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<(), CaliptraApiError> {
        // Wait for the microcontroller to finish executing

        let mut timeout_cycles = Self::CMD_TIMEOUT_CYCLES;

        while self.mbox().status().read().status().cmd_busy() {
            if timeout_cycles == 0 {
                return Err(CaliptraApiError::MailboxTimeout);
            }

            self.delay_one_cycle();

            timeout_cycles -= 1;
        }

        let status = self.mbox().status().read().status();

        if status.cmd_failure() {
            self.mbox().execute().write(|w| w.execute(false));

            return Err(CaliptraApiError::MailboxCmdFailed(
                if self.soc_ifc().cptra_fw_error_fatal().read() != 0 {
                    self.soc_ifc().cptra_fw_error_fatal().read()
                } else {
                    self.soc_ifc().cptra_fw_error_non_fatal().read()
                },
            ));
        }

        if status.cmd_complete() {
            self.mbox().execute().write(|w| w.execute(false));

            return Ok(());
        }

        if !status.data_ready() {
            return Err(CaliptraApiError::UnknownCommandStatus(status as u32));
        } else if buf.is_empty() {
            return Err(CaliptraApiError::MailboxUnexpectedResponse);
        }

        let dlen = self.mbox().dlen().read();

        mbox_read_fifo(self.mbox(), &mut buf[..dlen as usize]);

        self.mbox().execute().write(|w| w.execute(false));

        Ok(())
    }

    fn delay_one_cycle(&mut self);
}
