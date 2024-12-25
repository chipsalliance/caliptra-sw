/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{
    dma::Dma,
    helpers::words_from_bytes_be,
    iccm::Iccm,
    ml_dsa87::Mldsa87,
    recovery::RecoveryRegisterInterface,
    soc_reg::{DebugManufService, SocRegistersExternal},
    AsymEcc384, Csrng, Doe, EmuCtrl, HashSha256, HashSha512, HmacSha, KeyVault, MailboxExternal,
    MailboxInternal, MailboxRam, Sha512Accelerator, SocRegistersInternal, Uart,
};
use caliptra_api_types::{DbgManufServiceRegReq, SecurityState};
use caliptra_emu_bus::{Clock, Ram, Rom};
use caliptra_emu_cpu::{Pic, PicMmioRegisters};
use caliptra_emu_derive::Bus;
use caliptra_hw_model_types::{EtrngResponse, RandomEtrngResponses, RandomNibbles};
use std::path::PathBuf;
use tock_registers::registers::InMemoryRegister;

/// Default Deobfuscation engine key
pub const DEFAULT_DOE_KEY: [u8; 32] = [
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x7, 0x3B, 0x61, 0x8, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x9, 0x14, 0xDF, 0xF4,
];

pub struct TbServicesCb(pub Box<dyn FnMut(u8)>);
impl TbServicesCb {
    pub fn new(f: impl FnMut(u8) + 'static) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> Box<dyn FnMut(u8)> {
        std::mem::take(self).0
    }
}
impl Default for TbServicesCb {
    fn default() -> Self {
        Self(Box::new(|_| {}))
    }
}
impl std::fmt::Debug for TbServicesCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TbServicesCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl From<Box<dyn FnMut(u8) + 'static>> for TbServicesCb {
    fn from(value: Box<dyn FnMut(u8)>) -> Self {
        Self(value)
    }
}

type ReadyForFwCbSchedFn<'a> = dyn FnOnce(u64, Box<dyn FnOnce(&mut MailboxInternal)>) + 'a;
pub struct ReadyForFwCbArgs<'a> {
    pub mailbox: &'a mut MailboxInternal,
    pub(crate) sched_fn: Box<ReadyForFwCbSchedFn<'a>>,
}
impl<'a> ReadyForFwCbArgs<'a> {
    pub fn schedule_later(
        self,
        ticks_from_now: u64,
        cb: impl FnOnce(&mut MailboxInternal) + 'static,
    ) {
        (self.sched_fn)(ticks_from_now, Box::new(cb));
    }
}

type ReadyForFwFn = Box<dyn FnMut(ReadyForFwCbArgs)>;
pub struct ReadyForFwCb(pub ReadyForFwFn);
impl ReadyForFwCb {
    pub fn new(f: impl FnMut(ReadyForFwCbArgs) + 'static) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> ReadyForFwFn {
        std::mem::take(self).0
    }
}
impl Default for ReadyForFwCb {
    fn default() -> Self {
        Self(Box::new(|_| {}))
    }
}
impl std::fmt::Debug for ReadyForFwCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReadyForFwCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl From<Box<dyn FnMut(ReadyForFwCbArgs) + 'static>> for ReadyForFwCb {
    fn from(value: Box<dyn FnMut(ReadyForFwCbArgs)>) -> Self {
        Self(value)
    }
}

type UploadUpdateFwFn = Box<dyn FnMut(&mut MailboxInternal)>;
pub struct UploadUpdateFwCb(pub UploadUpdateFwFn);
impl UploadUpdateFwCb {
    pub fn new(f: impl FnMut(&mut MailboxInternal) + 'static) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> UploadUpdateFwFn {
        std::mem::take(self).0
    }
}
impl Default for UploadUpdateFwCb {
    fn default() -> Self {
        Self(Box::new(|_| {}))
    }
}
impl std::fmt::Debug for UploadUpdateFwCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UploadUpdateFwCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl From<Box<dyn FnMut(&mut MailboxInternal) + 'static>> for UploadUpdateFwCb {
    fn from(value: Box<dyn FnMut(&mut MailboxInternal)>) -> Self {
        Self(value)
    }
}

type DownloadCsrFn =
    Box<dyn FnMut(&mut MailboxInternal, &mut InMemoryRegister<u32, DebugManufService::Register>)>;
pub struct DownloadIdevidCsrCb(pub DownloadCsrFn);
impl DownloadIdevidCsrCb {
    pub fn new(
        f: impl FnMut(&mut MailboxInternal, &mut InMemoryRegister<u32, DebugManufService::Register>)
            + 'static,
    ) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> DownloadCsrFn {
        std::mem::take(self).0
    }
}
impl Default for DownloadIdevidCsrCb {
    fn default() -> Self {
        Self(Box::new(|_, _| {}))
    }
}
impl std::fmt::Debug for DownloadIdevidCsrCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DownloadCsrCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl
    From<
        Box<
            dyn FnMut(&mut MailboxInternal, &mut InMemoryRegister<u32, DebugManufService::Register>)
                + 'static,
        >,
    > for DownloadIdevidCsrCb
{
    fn from(
        value: Box<
            dyn FnMut(
                &mut MailboxInternal,
                &mut InMemoryRegister<u32, DebugManufService::Register>,
            ),
        >,
    ) -> Self {
        Self(value)
    }
}

pub struct ActionCb(Box<dyn FnMut()>);
impl ActionCb {
    pub fn new(f: impl FnMut() + 'static) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> Box<dyn FnMut()> {
        std::mem::take(self).0
    }
}
impl Default for ActionCb {
    fn default() -> Self {
        Self(Box::new(|| {}))
    }
}
impl std::fmt::Debug for ActionCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ActionCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl From<Box<dyn FnMut() + 'static>> for ActionCb {
    fn from(value: Box<dyn FnMut()>) -> Self {
        Self(value)
    }
}

/// Caliptra Root Bus Arguments
pub struct CaliptraRootBusArgs {
    pub rom: Vec<u8>,
    pub log_dir: PathBuf,
    // The security state wires provided to caliptra_top
    pub security_state: SecurityState,
    pub dbg_manuf_service_req: DbgManufServiceRegReq,
    pub debug_intent: bool,

    /// Callback to customize application behavior when
    /// a write to the tb-services register write is performed.
    pub tb_services_cb: TbServicesCb,
    pub ready_for_fw_cb: ReadyForFwCb,
    pub upload_update_fw: UploadUpdateFwCb,
    pub bootfsm_go_cb: ActionCb,
    pub download_idevid_csr_cb: DownloadIdevidCsrCb,

    // The obfuscation key, as passed to caliptra-top
    pub cptra_obf_key: [u32; 8],

    pub itrng_nibbles: Option<Box<dyn Iterator<Item = u8>>>,
    pub etrng_responses: Box<dyn Iterator<Item = EtrngResponse>>,
}
impl Default for CaliptraRootBusArgs {
    fn default() -> Self {
        Self {
            rom: Default::default(),
            log_dir: Default::default(),
            security_state: Default::default(),
            dbg_manuf_service_req: Default::default(),
            debug_intent: false,
            tb_services_cb: Default::default(),
            ready_for_fw_cb: Default::default(),
            upload_update_fw: Default::default(),
            bootfsm_go_cb: Default::default(),
            download_idevid_csr_cb: Default::default(),
            cptra_obf_key: words_from_bytes_be(&DEFAULT_DOE_KEY),
            itrng_nibbles: Some(Box::new(RandomNibbles::new_from_thread_rng())),
            etrng_responses: Box::new(RandomEtrngResponses::new_from_stdrng()),
        }
    }
}

#[derive(Bus)]
#[handle_dma_fn(handle_dma)]
pub struct CaliptraRootBus {
    #[peripheral(offset = 0x0000_0000, mask = 0x0fff_ffff)]
    pub rom: Rom,

    #[peripheral(offset = 0x1000_0000, mask = 0x0000_7fff)]
    pub doe: Doe,

    #[peripheral(offset = 0x1000_8000, mask = 0x0000_7fff)]
    pub ecc384: AsymEcc384,

    #[peripheral(offset = 0x1001_0000, mask = 0x0000_07ff)]
    pub hmac: HmacSha,

    #[peripheral(offset = 0x1001_8000, mask = 0x0000_7fff)]
    pub key_vault: KeyVault,

    #[peripheral(offset = 0x1002_0000, mask = 0x0000_7fff)]
    pub sha512: HashSha512,

    #[peripheral(offset = 0x1002_8000, mask = 0x0000_7fff)]
    pub sha256: HashSha256,

    #[peripheral(offset = 0x1003_0000, mask = 0x0000_ffff)]
    pub ml_dsa87: Mldsa87,

    // We set I3C at 0x1004_0000 and EC is at 0x100 offset
    #[peripheral(offset = 0x1004_0100, mask = 0x0000_7fff)] // TODO
    pub recovery: RecoveryRegisterInterface,

    #[peripheral(offset = 0x4000_0000, mask = 0x0fff_ffff)]
    pub iccm: Iccm,

    #[peripheral(offset = 0x2000_1000, mask = 0x0000_0fff)]
    pub uart: Uart,

    #[peripheral(offset = 0x2000_2000, mask = 0x0000_1fff)]
    pub csrng: Csrng,

    #[peripheral(offset = 0x2000_f000, mask = 0x0000_0fff)]
    pub ctrl: EmuCtrl,

    #[peripheral(offset = 0x3000_0000, mask = 0x0001_ffff)]
    pub mailbox_sram: MailboxRam,

    #[peripheral(offset = 0x3002_0000, mask = 0x0000_0fff)]
    pub mailbox: MailboxInternal,

    #[peripheral(offset = 0x3002_1000, mask = 0x0000_0fff)]
    pub sha512_acc: Sha512Accelerator,

    #[peripheral(offset = 0x3002_2000, mask = 0x0000_0fff)]
    pub dma: Dma,

    #[peripheral(offset = 0x3003_0000, mask = 0x0000_ffff)]
    pub soc_reg: SocRegistersInternal,

    #[peripheral(offset = 0x5000_0000, mask = 0x0fff_ffff)]
    pub dccm: Ram,

    #[peripheral(offset = 0x6000_0000, mask = 0x0000_ffff)]
    pub pic_regs: PicMmioRegisters,
}

impl CaliptraRootBus {
    pub const ROM_SIZE: usize = 96 * 1024;
    pub const ICCM_SIZE: usize = 128 * 1024;
    pub const DCCM_SIZE: usize = 256 * 1024;

    pub fn new(clock: &Clock, mut args: CaliptraRootBusArgs) -> Self {
        let mut key_vault = KeyVault::new();
        let mailbox_ram = MailboxRam::new();
        let mailbox = MailboxInternal::new(clock, mailbox_ram.clone());
        let rom = Rom::new(std::mem::take(&mut args.rom));
        let iccm = Iccm::new(clock);
        let pic = Pic::new();
        let itrng_nibbles = args.itrng_nibbles.take();
        let soc_reg = SocRegistersInternal::new(clock, mailbox.clone(), iccm.clone(), &pic, args);
        if !soc_reg.is_debug_locked() {
            // When debug is possible, the key-vault is initialized with a debug value...
            // This is necessary to match the behavior of the RTL.
            key_vault.clear_keys_with_debug_values(false);
        }

        let sha512 = HashSha512::new(clock, key_vault.clone());

        Self {
            rom,
            doe: Doe::new(clock, key_vault.clone(), soc_reg.clone()),
            ecc384: AsymEcc384::new(clock, key_vault.clone(), sha512.clone()),
            hmac: HmacSha::new(clock, key_vault.clone()),
            key_vault: key_vault.clone(),
            sha512,
            sha256: HashSha256::new(clock),
            ml_dsa87: Mldsa87::new(clock, key_vault.clone()),
            recovery: RecoveryRegisterInterface::new(),
            iccm,
            dccm: Ram::new(vec![0; Self::DCCM_SIZE]),
            uart: Uart::new(),
            ctrl: EmuCtrl::new(),
            soc_reg,
            mailbox_sram: mailbox_ram.clone(),
            mailbox,
            sha512_acc: Sha512Accelerator::new(clock, mailbox_ram),
            dma: Dma::new(clock),
            csrng: Csrng::new(itrng_nibbles.unwrap()),
            pic_regs: pic.mmio_regs(clock),
        }
    }

    pub fn soc_to_caliptra_bus(&self) -> SocToCaliptraBus {
        SocToCaliptraBus {
            mailbox: self.mailbox.as_external(),
            sha512_acc: self.sha512_acc.clone(),
            soc_ifc: self.soc_reg.external_regs(),
        }
    }

    fn handle_dma(&mut self) {
        let mut dma = self.dma.clone();
        dma.do_dma_handling(self)
    }
}

#[derive(Bus)]
pub struct SocToCaliptraBus {
    #[peripheral(offset = 0x3002_0000, mask = 0x0000_0fff)]
    mailbox: MailboxExternal,

    #[peripheral(offset = 0x3002_1000, mask = 0x0000_0fff)]
    sha512_acc: Sha512Accelerator,

    #[peripheral(offset = 0x3003_0000, mask = 0x0000_ffff)]
    soc_ifc: SocRegistersExternal,
}

#[cfg(test)]
mod tests {
    use crate::KeyUsage;

    use super::*;

    #[test]
    fn test_keyvault_init_val_in_debug_unlocked_mode() {
        let clock = Clock::new();
        let mut root_bus = CaliptraRootBus::new(
            &clock,
            CaliptraRootBusArgs {
                security_state: *SecurityState::default().set_debug_locked(false),
                ..CaliptraRootBusArgs::default()
            },
        );
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_key(true);

        root_bus
            .key_vault
            .write_key(1, &[0x00, 0x11, 0x22, 0x33], key_usage.into())
            .unwrap();

        // The key-entry will still have the "init data" in the unwritten words.
        // See chipsalliace/caliptra-rtl#114
        assert_eq!(
            root_bus.key_vault.read_key(1, key_usage).unwrap(),
            [
                0x00_u8, 0x11, 0x22, 0x33, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
            ]
        );
    }

    #[test]
    fn test_keyvault_init_val_in_debug_locked_mode() {
        let clock = Clock::new();
        let mut root_bus = CaliptraRootBus::new(
            &clock,
            CaliptraRootBusArgs {
                security_state: *SecurityState::default().set_debug_locked(true),
                ..CaliptraRootBusArgs::default()
            },
        );
        let mut key_usage = KeyUsage::default();
        key_usage.set_hmac_key(true);

        root_bus
            .key_vault
            .write_key(1, &[0x00, 0x11, 0x22, 0x33], key_usage.into())
            .unwrap();

        // The key-entry will still have the "init data" in the unwritten words.
        // See chipsalliace/caliptra-rtl#114
        assert_eq!(
            root_bus.key_vault.read_key(1, key_usage).unwrap(),
            [
                0x00_u8, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }
}
