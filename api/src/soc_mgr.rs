// Licensed under the Apache-2.0 license

use crate::{
    calc_checksum,
    mailbox::{
        mbox_read_response, mbox_write_fifo, MailboxReqHeader, MailboxRespHeader, Request,
        Response, StashMeasurementReq,
    },
    CaliptraApiError,
};
use caliptra_api_types::Fuses;
use core::mem;
use ureg::MmioMut;
use zerocopy::{AsBytes, FromBytes};

pub const NUM_PAUSERS: usize = 5;

/// Implementation of the `SocManager` trait for a `RealSocManager`.
///
/// # Example
///
/// ```rust
/// use caliptra_api::SocManager;
/// use ureg::RealMmioMut;
/// struct RealSocManager;
/// const CPTRA_SOC_IFC_ADDR: u32 = 0x3003_0000;
/// const CPTRA_SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
/// const CPTRA_SOC_SHA512_ACC_ADDR: u32 = 0x3002_1000;
/// const CPTRA_SOC_MBOX_ADDR: u32 = 0x3002_0000;
/// const fn caliptra_address_remap(addr : u32) -> u32 {
///     addr
/// }
/// impl SocManager for RealSocManager {
///     /// Address of the mailbox, remapped for the SoC.
///     const SOC_MBOX_ADDR: u32 = caliptra_address_remap(CPTRA_SOC_MBOX_ADDR);
///
///     /// Address of the SoC interface, remapped for the SoC.
///     const SOC_IFC_ADDR: u32 = caliptra_address_remap(CPTRA_SOC_IFC_ADDR);
///
///     /// Address of the SoC TRNG interface, remapped for the SoC.
///     const SOC_IFC_TRNG_ADDR: u32 = caliptra_address_remap(CPTRA_SOC_IFC_TRNG_ADDR);
///
///     /// Address of the SHA-512 accelerator, remapped for the SoC.
///     const SOC_SHA512_ACC_ADDR: u32 = caliptra_address_remap(CPTRA_SOC_SHA512_ACC_ADDR);
///
///     /// Maximum number of wait cycles.
///     const MAX_WAIT_CYCLES: u32 = 400000;
///
///     /// Type alias for mutable memory-mapped I/O.
///     type TMmio<'a> = RealMmioMut<'a>;
///
///     /// Returns a mutable reference to the memory-mapped I/O.
///     fn mmio_mut(&mut self) -> Self::TMmio<'_> {
///         ureg::RealMmioMut::default()
///     }
///
///     /// Provides a delay function to be invoked when polling mailbox status.
///     fn delay(&mut self) {
///         //real_soc_delay_fn(1);
///     }
/// }
/// ```
pub trait SocManager {
    const SOC_IFC_ADDR: u32;
    const SOC_MBOX_ADDR: u32;
    const SOC_SHA512_ACC_ADDR: u32;
    const SOC_IFC_TRNG_ADDR: u32;

    const MAX_WAIT_CYCLES: u32;

    type TMmio<'a>: MmioMut
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_>;

    // Provide a time base for mailbox status polling loop.
    fn delay(&mut self);

    /// Set up valid PAUSERs for mailbox access.
    fn setup_mailbox_users(&mut self, apb_pausers: &[u32]) -> Result<(), CaliptraApiError> {
        if apb_pausers.len() > NUM_PAUSERS {
            return Err(CaliptraApiError::UnableToSetPauser);
        }

        for (idx, apb_pauser) in apb_pausers.iter().enumerate() {
            if self
                .soc_ifc()
                .cptra_mbox_axi_user_lock()
                .at(idx)
                .read()
                .lock()
            {
                return Err(CaliptraApiError::UnableToSetPauser);
            }

            self.soc_ifc()
                .cptra_mbox_valid_axi_user()
                .at(idx)
                .write(|_| *apb_pauser);
            self.soc_ifc()
                .cptra_mbox_axi_user_lock()
                .at(idx)
                .write(|w| w.lock(true));
        }
        Ok(())
    }

    /// Initializes the fuse values and locks them in until the next reset.
    ///
    /// # Errors
    ///
    /// If the cptra_fuse_wr_done has already been written, or the
    /// hardware prevents cptra_fuse_wr_done from being set.
    fn init_fuses(&mut self, fuses: &Fuses) -> Result<(), CaliptraApiError> {
        if !self.soc_ifc().cptra_reset_reason().read().warm_reset()
            && self.soc_ifc().cptra_fuse_wr_done().read().done()
        {
            return Err(CaliptraApiError::FusesAlreadyIniitalized);
        }

        self.soc_ifc().fuse_uds_seed().write(&fuses.uds_seed);
        self.soc_ifc()
            .fuse_field_entropy()
            .write(&fuses.field_entropy);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash()
            .write(&fuses.key_manifest_pk_hash);
        self.soc_ifc().fuse_key_manifest_pk_hash_mask().write(&[
            fuses.key_manifest_pk_hash_mask.into(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        self.soc_ifc()
            .cptra_owner_pk_hash()
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
            .fuse_lms_revocation()
            .write(|_| fuses.fuse_lms_revocation);
        self.soc_ifc()
            .fuse_soc_stepping_id()
            .write(|w| w.soc_stepping_id(fuses.soc_stepping_id.into()));
        self.soc_ifc()
            .fuse_manuf_dbg_unlock_token()
            .write(&fuses.manuf_dbg_unlock_token);

        self.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));

        if !self.soc_ifc().cptra_fuse_wr_done().read().done() {
            return Err(CaliptraApiError::FuseDoneNotSet);
        }
        Ok(())
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
                Self::SOC_IFC_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral TRNG registers
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc_trng(&mut self) -> caliptra_registers::soc_ifc_trng::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::soc_ifc_trng::RegisterBlock::new_with_mmio(
                Self::SOC_IFC_TRNG_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mbox peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                Self::SOC_MBOX_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the sha512_acc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_sha512_acc(&mut self) -> caliptra_registers::sha512_acc::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::sha512_acc::RegisterBlock::new_with_mmio(
                Self::SOC_SHA512_ACC_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// Executes `cmd` with request data `buf`. Returns `Ok(Some(_))` if
    /// the uC responded with data, `Ok(None)` if the uC indicated success
    /// without data, Err(CaliptraApiError::MailboxCmdFailed) if the microcontroller
    /// responded with an error, or other errors if there was a problem
    /// communicating with the mailbox.
    fn mailbox_exec<'r>(
        &mut self,
        cmd: u32,
        buf: &[u8],
        resp_data: &'r mut [u8],
    ) -> core::result::Result<Option<&'r [u8]>, CaliptraApiError> {
        self.start_mailbox_exec(cmd, buf)?;
        self.finish_mailbox_exec(resp_data)
    }

    /// Send a command to the mailbox but don't wait for the response
    fn start_mailbox_exec(
        &mut self,
        cmd: u32,
        buf: &[u8],
    ) -> core::result::Result<(), CaliptraApiError> {
        // Read a 0 to get the lock
        if self.soc_mbox().lock().read().lock() {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }

        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the PAUSER check or some other issue
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToReadMailbox);
        }

        self.soc_mbox().cmd().write(|_| cmd);
        mbox_write_fifo(&self.soc_mbox(), buf)?;

        // Ask the microcontroller to execute this command
        self.soc_mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

    fn finish_mailbox_exec<'r>(
        &mut self,
        resp_data: &'r mut [u8],
    ) -> core::result::Result<Option<&'r [u8]>, CaliptraApiError> {
        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = Self::MAX_WAIT_CYCLES; // 100ms @400MHz
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.delay();
            timeout_cycles -= 1;
            if timeout_cycles == 0 {
                return Err(CaliptraApiError::MailboxTimeout);
            }
        }
        let status = self.soc_mbox().status().read().status();
        if status.cmd_failure() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            let soc_ifc = self.soc_ifc();
            return Err(CaliptraApiError::MailboxCmdFailed(
                if soc_ifc.cptra_fw_error_fatal().read() != 0 {
                    soc_ifc.cptra_fw_error_fatal().read()
                } else {
                    soc_ifc.cptra_fw_error_non_fatal().read()
                },
            ));
        }
        if status.cmd_complete() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Ok(None);
        }
        if !status.data_ready() {
            return Err(CaliptraApiError::UnknownCommandStatus(status as u32));
        }

        let res = mbox_read_response(self.soc_mbox(), resp_data);

        self.soc_mbox().execute().write(|w| w.execute(false));

        let buf = res?;

        Ok(Some(buf))
    }

    /// Executes a typed request and (if success), returns the typed response.
    /// The checksum field of the request is calculated, and the checksum of the
    /// response is validated.
    fn mailbox_exec_req<R: Request>(
        &mut self,
        mut req: R,
        resp_bytes: &mut [u8],
    ) -> core::result::Result<R::Resp, CaliptraApiError> {
        if mem::size_of::<R>() < mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraApiError::MailboxReqTypeTooSmall);
        }
        if mem::size_of::<R::Resp>() < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }
        if R::Resp::MIN_SIZE < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }
        let (header_bytes, payload_bytes) = req
            .as_bytes_mut()
            .split_at_mut(mem::size_of::<MailboxReqHeader>());

        let mut header = MailboxReqHeader::read_from(header_bytes as &[u8]).unwrap();
        header.chksum = calc_checksum(R::ID.into(), payload_bytes);
        header_bytes.copy_from_slice(header.as_bytes());

        let Some(data) = SocManager::mailbox_exec(self, R::ID.into(), req.as_bytes(), resp_bytes)? else {
                return Err(CaliptraApiError::MailboxNoResponseData);
        };

        if data.len() < R::Resp::MIN_SIZE || data.len() > mem::size_of::<R::Resp>() {
            return Err(CaliptraApiError::MailboxUnexpectedResponseLen {
                expected_min: R::Resp::MIN_SIZE as u32,
                expected_max: mem::size_of::<R::Resp>() as u32,
                actual: data.len() as u32,
            });
        }

        let mut response = R::Resp::new_zeroed();
        response.as_bytes_mut()[..data.len()].copy_from_slice(data);

        let response_header = MailboxRespHeader::read_from_prefix(data).unwrap();
        let actual_checksum = calc_checksum(0, &data[4..]);
        if actual_checksum != response_header.chksum {
            return Err(CaliptraApiError::MailboxRespInvalidChecksum {
                expected: response_header.chksum,
                actual: actual_checksum,
            });
        }
        if response_header.fips_status != MailboxRespHeader::FIPS_STATUS_APPROVED {
            return Err(CaliptraApiError::MailboxRespInvalidFipsStatus(
                response_header.fips_status,
            ));
        }
        Ok(response)
    }

    fn send_stash_measurement_req(
        &mut self,
        req: StashMeasurementReq,
        response_packet: &mut [u8],
    ) -> Result<(), CaliptraApiError> {
        let resp = self.mailbox_exec_req(req, response_packet)?;
        if resp.dpe_result == 0 {
            return Ok(());
        }
        Err(CaliptraApiError::StashMeasurementFailed)
    }
}
