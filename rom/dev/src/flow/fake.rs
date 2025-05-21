/*++

Licensed under the Apache-2.0 license.

File Name:

    fake.rs

Abstract:

    File contains the implementation of the fake ROM reset flows

--*/

#[cfg(not(feature = "fake-rom"))]
compile_error!("This file should NEVER be included except for the fake-rom feature");

use crate::fht;
use crate::flow::cold_reset::fw_processor::FirmwareProcessor;
use crate::flow::update_reset;
use crate::flow::warm_reset;
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
use caliptra_common::keyids::KEY_ID_ROM_FMC_CDI;
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::cprintln;
use caliptra_drivers::Lifecycle;
use caliptra_drivers::LmsResult;
use caliptra_drivers::VendorEccPubKeyRevocation;
use caliptra_drivers::*;
use caliptra_error::CaliptraError;
use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use caliptra_registers::sha512_acc::Sha512AccCsr;
use core::ops::Range;

const FAKE_LDEV_ECC_TBS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ldev_tbs.der"));
const FAKE_LDEV_ECC_PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4xN([
        0x842C00AF, 0x05ACCCEB, 0x14514E2D, 0x37B0C3AA, 0xA218F150, 0x57F1DCB8, 0x24A21498,
        0x0B744688, 0xA0888A02, 0x97FA7DC5, 0xE1EAD8CA, 0x1291DB22,
    ]),
    y: Array4xN([
        0x9C28EB86, 0x78BCE800, 0x822C0722, 0x8F416AE4, 0x9D218E5D, 0xA2F2D1A8, 0xA27DC19A,
        0xDF668A74, 0x628999D2, 0x22B40159, 0xD8076FAF, 0xBB8C5EDB,
    ]),
};
const FAKE_LDEV_ECC_SIG: Ecc384Signature = Ecc384Signature {
    r: Array4xN(include!(concat!(env!("OUT_DIR"), "/ldev_sig_r_words.txt"))),
    s: Array4xN(include!(concat!(env!("OUT_DIR"), "/ldev_sig_s_words.txt"))),
};

const FAKE_FMC_ALIAS_ECC_TBS: [u8; 767] = [
    0x30, 0x82, 0x2, 0xfb, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x14, 0x7, 0xe4, 0x2, 0x71, 0x45, 0x8f,
    0x86, 0x4b, 0x75, 0x27, 0xd8, 0x91, 0xc5, 0xc, 0xb, 0xd7, 0xf4, 0xc3, 0x60, 0x9d, 0x30, 0xa,
    0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x3, 0x30, 0x70, 0x31, 0x23, 0x30, 0x21, 0x6,
    0x3, 0x55, 0x4, 0x3, 0xc, 0x1a, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61, 0x20, 0x32,
    0x2e, 0x30, 0x20, 0x45, 0x63, 0x63, 0x33, 0x38, 0x34, 0x20, 0x4c, 0x44, 0x65, 0x76, 0x49, 0x44,
    0x31, 0x49, 0x30, 0x47, 0x6, 0x3, 0x55, 0x4, 0x5, 0x13, 0x40, 0x44, 0x45, 0x39, 0x36, 0x41,
    0x34, 0x35, 0x30, 0x46, 0x32, 0x33, 0x41, 0x38, 0x45, 0x34, 0x41, 0x35, 0x33, 0x33, 0x33, 0x30,
    0x30, 0x35, 0x45, 0x36, 0x30, 0x42, 0x46, 0x43, 0x46, 0x34, 0x44, 0x33, 0x44, 0x41, 0x38, 0x46,
    0x41, 0x31, 0x36, 0x30, 0x33, 0x46, 0x41, 0x46, 0x42, 0x36, 0x30, 0x35, 0x44, 0x32, 0x42, 0x32,
    0x32, 0x43, 0x34, 0x34, 0x46, 0x34, 0x43, 0x32, 0x32, 0x39, 0x32, 0x30, 0x22, 0x18, 0xf, 0x32,
    0x30, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0xf,
    0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30,
    0x73, 0x31, 0x26, 0x30, 0x24, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x1d, 0x43, 0x61, 0x6c, 0x69,
    0x70, 0x74, 0x72, 0x61, 0x20, 0x32, 0x2e, 0x30, 0x20, 0x45, 0x63, 0x63, 0x33, 0x38, 0x34, 0x20,
    0x46, 0x4d, 0x43, 0x20, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x31, 0x49, 0x30, 0x47, 0x6, 0x3, 0x55,
    0x4, 0x5, 0x13, 0x40, 0x38, 0x37, 0x45, 0x34, 0x30, 0x32, 0x37, 0x31, 0x34, 0x35, 0x38, 0x46,
    0x38, 0x36, 0x34, 0x42, 0x37, 0x35, 0x32, 0x37, 0x44, 0x38, 0x39, 0x31, 0x43, 0x35, 0x30, 0x43,
    0x30, 0x42, 0x44, 0x37, 0x46, 0x34, 0x43, 0x33, 0x36, 0x30, 0x39, 0x44, 0x37, 0x34, 0x34, 0x30,
    0x30, 0x41, 0x44, 0x41, 0x33, 0x37, 0x32, 0x33, 0x32, 0x32, 0x44, 0x36, 0x31, 0x33, 0x44, 0x33,
    0x32, 0x46, 0x35, 0x45, 0x30, 0x76, 0x30, 0x10, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2,
    0x1, 0x6, 0x5, 0x2b, 0x81, 0x4, 0x0, 0x22, 0x3, 0x62, 0x0, 0x4, 0x12, 0xc9, 0xbc, 0xf6, 0x87,
    0xfb, 0x67, 0xe0, 0x54, 0xbf, 0x9, 0x97, 0xb9, 0xef, 0xf5, 0x4, 0xbd, 0x7b, 0x87, 0x9e, 0xd2,
    0x4a, 0xfe, 0xd8, 0xd1, 0xa, 0x43, 0xcf, 0xe6, 0x92, 0xeb, 0x55, 0x41, 0x1, 0x84, 0x3c, 0x6a,
    0xb1, 0x3e, 0x46, 0x4c, 0x12, 0x3, 0xe3, 0x62, 0xea, 0x36, 0x7d, 0xd4, 0x99, 0xb7, 0x40, 0x1a,
    0x77, 0x9e, 0x92, 0x21, 0xa5, 0xa1, 0x1d, 0xc2, 0x62, 0x56, 0x47, 0x3, 0xcf, 0xaa, 0x54, 0x2e,
    0x81, 0x3f, 0xd9, 0x82, 0xf9, 0xc1, 0x4f, 0xa, 0xd0, 0x4, 0x8a, 0xd7, 0xdd, 0x3d, 0x45, 0x85,
    0xe6, 0x50, 0x3d, 0xfc, 0x1, 0x81, 0xeb, 0xcf, 0x69, 0xcd, 0xf9, 0xa3, 0x82, 0x1, 0x4d, 0x30,
    0x82, 0x1, 0x49, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x8, 0x30, 0x6,
    0x1, 0x1, 0xff, 0x2, 0x1, 0x3, 0x30, 0xe, 0x6, 0x3, 0x55, 0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4,
    0x3, 0x2, 0x2, 0x4, 0x30, 0x1f, 0x6, 0x6, 0x67, 0x81, 0x5, 0x5, 0x4, 0x4, 0x4, 0x15, 0x30,
    0x13, 0x4, 0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x30, 0x81, 0xc1, 0x6, 0x6, 0x67, 0x81, 0x5, 0x5, 0x4, 0x5, 0x4, 0x81, 0xb6, 0x30,
    0x81, 0xb3, 0x30, 0x60, 0x83, 0x2, 0x1, 0x7, 0xa6, 0x3f, 0x30, 0x3d, 0x6, 0x9, 0x60, 0x86,
    0x48, 0x1, 0x65, 0x3, 0x4, 0x2, 0x2, 0x4, 0x30, 0x34, 0x6a, 0xb7, 0x91, 0x5b, 0x12, 0x2e, 0x78,
    0xac, 0xca, 0xeb, 0x20, 0xcb, 0xbf, 0x6, 0xa, 0x84, 0x31, 0xd8, 0x44, 0x57, 0x46, 0xc9, 0x70,
    0x7e, 0x4b, 0x94, 0x39, 0xd9, 0x44, 0xbd, 0xb7, 0xb, 0x8d, 0x40, 0xd4, 0xcf, 0x4b, 0xa8, 0x18,
    0x25, 0xad, 0x55, 0xe8, 0xd2, 0xc0, 0x64, 0x85, 0x87, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1, 0x89, 0xb,
    0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x5f, 0x49, 0x4e, 0x46, 0x4f, 0x8a, 0x5, 0x0, 0xd0, 0x0,
    0x0, 0x1, 0x30, 0x4f, 0x83, 0x2, 0x1, 0x9, 0xa6, 0x3f, 0x30, 0x3d, 0x6, 0x9, 0x60, 0x86, 0x48,
    0x1, 0x65, 0x3, 0x4, 0x2, 0x2, 0x4, 0x30, 0x90, 0x4b, 0xef, 0x4e, 0xf4, 0x59, 0xe8, 0x29, 0xff,
    0xf6, 0x8d, 0xc3, 0x2f, 0xd1, 0x15, 0xd3, 0xdc, 0x4d, 0xd0, 0xa, 0xf8, 0xd3, 0x1b, 0xb, 0x46,
    0x8e, 0xcf, 0xa6, 0x61, 0xbe, 0x17, 0x6f, 0x7f, 0x7b, 0x6, 0x16, 0x34, 0x28, 0x20, 0x3e, 0x8f,
    0xa7, 0x17, 0x43, 0x70, 0xdc, 0x8e, 0xfb, 0x89, 0x8, 0x46, 0x4d, 0x43, 0x5f, 0x49, 0x4e, 0x46,
    0x4f, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0x87, 0xe4, 0x2, 0x71, 0x45,
    0x8f, 0x86, 0x4b, 0x75, 0x27, 0xd8, 0x91, 0xc5, 0xc, 0xb, 0xd7, 0xf4, 0xc3, 0x60, 0x9d, 0x30,
    0x1f, 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xde, 0x96, 0xa4, 0x50,
    0xf2, 0x3a, 0x8e, 0x4a, 0x53, 0x33, 0x0, 0x5e, 0x60, 0xbf, 0xcf, 0x4d, 0x3d, 0xa8, 0xfa, 0x16,
];

const FAKE_FMC_ALIAS_ECC_PUB_KEY: Ecc384PubKey = Ecc384PubKey {
    x: Array4xN([
        315210998, 2281400288, 1421805975, 3119510788, 3178989470, 3528130264, 3507110863,
        3868388181, 1090618428, 1790000710, 1276249059, 1659516541,
    ]),
    y: Array4xN([
        3566843712, 444046994, 564502813, 3261224519, 63941204, 780222425, 2197406031, 181404810,
        3621600581, 2246463549, 4227957227, 3479817721,
    ]),
};
const FAKE_FMC_ALIAS_ECC_SIG: Ecc384Signature = Ecc384Signature {
    r: Array4xN([
        0xab76e15, 0x78394668, 0x9eaea815, 0x3e9e7aa5, 0xb954fcd0, 0xdd2ca3f, 0x9d541a9,
        0xf8700a0a, 0x32977111, 0xe8b3b34c, 0x675921b9, 0x356872b6,
    ]),
    s: Array4xN([
        0x86eb9238, 0xef7d9cee, 0x5eeef4ce, 0x415ac27e, 0x85105347, 0x990a015, 0x7920e66e,
        0x8fdbd713, 0xd17463a0, 0x706c6e13, 0x6abe4a30, 0x24604f1f,
    ]),
};

const FAKE_LDEV_MLDSA_SIG: [u32; 1157] =
    include!(concat!(env!("OUT_DIR"), "/ldevid_mldsa_sig.txt"));

const FAKE_LDEV_MLDSA_PUB_KEY: [u32; 648] =
    include!(concat!(env!("OUT_DIR"), "/ldevid_mldsa_pub_key.txt"));

const FAKE_LDEV_MLDSA_TBS: [u8; 3048] = include!(concat!(env!("OUT_DIR"), "/ldevid_mldsa_tbs.txt"));

const FAKE_FMC_ALIAS_MLDSA_SIG: [u32; 1157] =
    include!(concat!(env!("OUT_DIR"), "/fmc_alias_mldsa_sig.txt"));

const FAKE_FMC_ALIAS_MLDSA_PUB_KEY: [u32; 648] =
    include!(concat!(env!("OUT_DIR"), "/fmc_alias_mldsa_pub_key.txt"));

const FAKE_FMC_ALIAS_MLDSA_TBS: [u8; 3247] =
    include!(concat!(env!("OUT_DIR"), "/fmc_alias_mldsa_tbs.txt"));

pub struct FakeRomFlow {}

impl FakeRomFlow {
    /// Execute ROM Flows based on reset reason
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        let reset_reason = env.soc_ifc.reset_reason();
        match reset_reason {
            // Cold Reset Flow
            ResetReason::ColdReset => {
                cprintln!("[fake-rom-cold-reset] ++");
                report_boot_status(ColdResetStarted.into());

                // Zeroize the key vault in the fake ROM flow
                unsafe { KeyVault::zeroize() };

                env.soc_ifc.flow_status_set_ready_for_mb_processing();

                fht::initialize_fht(env);

                // SKIP Execute IDEVID layer
                // LDEVID cert
                copy_canned_ldev_cert(env)?;
                // LDEVID cdi
                initialize_fake_ldevid_cdi(env)?;

                // Unlock the SHA Acc by creating a SHA Acc operation and dropping it.
                // In real ROM, this is done as part of executing the SHA-ACC KAT.
                let sha_op = env
                    .sha2_512_384_acc
                    .try_start_operation(ShaAccLockState::AssumedLocked)
                    .unwrap();
                drop(sha_op);

                // Download and validate firmware.
                _ = FirmwareProcessor::process(env)?;

                // FMC Alias Cert
                copy_canned_fmc_alias_cert(env)?;

                cprintln!("[fake-rom-cold-reset] --");
                report_boot_status(ColdResetComplete.into());

                Ok(())
            }

            // Warm Reset Flow
            ResetReason::WarmReset => warm_reset::WarmResetFlow::run(env),

            // Update Reset Flow
            ResetReason::UpdateReset => update_reset::UpdateResetFlow::run(env),

            // Unknown/Spurious Reset Flow
            ResetReason::Unknown => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),
        }
    }
}

// Used to derive the firmware's key ladder.
fn initialize_fake_ldevid_cdi(env: &mut RomEnv) -> CaliptraResult<()> {
    let fake_key = Array4x16::from([0x1234_5678u32; 16]);
    env.hmac.hmac(
        HmacKey::Array4x16(&fake_key),
        HmacData::Slice(b""),
        &mut env.trng,
        KeyWriteArgs::new(KEY_ID_ROM_FMC_CDI, KeyUsage::default().set_hmac_key_en()).into(),
        HmacMode::Hmac512,
    )
}

pub fn copy_canned_ldev_cert(env: &mut RomEnv) -> CaliptraResult<()> {
    let data_vault = &mut env.persistent_data.get_mut().data_vault;

    // Store signature
    data_vault.set_ldev_dice_ecc_signature(&FAKE_LDEV_ECC_SIG);
    data_vault.set_ldev_dice_mldsa_signature(&LEArray4x1157::from(&FAKE_LDEV_MLDSA_SIG));

    // Store pub key
    data_vault.set_ldev_dice_ecc_pub_key(&FAKE_LDEV_ECC_PUB_KEY);
    data_vault.set_ldev_dice_mldsa_pub_key(&LEArray4x648::from(&FAKE_LDEV_MLDSA_PUB_KEY));

    // Copy TBS to DCCM
    let tbs = &FAKE_LDEV_ECC_TBS;
    env.persistent_data.get_mut().fht.ecc_ldevid_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .ecc_ldevid_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    let tbs = &FAKE_LDEV_MLDSA_TBS;
    env.persistent_data.get_mut().fht.mldsa_ldevid_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .mldsa_ldevid_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    Ok(())
}

pub fn copy_canned_fmc_alias_cert(env: &mut RomEnv) -> CaliptraResult<()> {
    let data_vault = &mut env.persistent_data.get_mut().data_vault;

    // Store signature
    data_vault.set_fmc_dice_ecc_signature(&FAKE_FMC_ALIAS_ECC_SIG);
    data_vault.set_fmc_dice_mldsa_signature(&LEArray4x1157::from(&FAKE_FMC_ALIAS_MLDSA_SIG));

    // Store pub key
    data_vault.set_fmc_ecc_pub_key(&FAKE_FMC_ALIAS_ECC_PUB_KEY);
    data_vault.set_fmc_mldsa_pub_key(&LEArray4x648::from(&FAKE_FMC_ALIAS_MLDSA_PUB_KEY));

    // Copy TBS to DCCM
    let tbs = &FAKE_FMC_ALIAS_ECC_TBS;
    env.persistent_data.get_mut().fht.ecc_fmcalias_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .ecc_fmcalias_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    let tbs = &FAKE_FMC_ALIAS_MLDSA_TBS;
    env.persistent_data.get_mut().fht.mldsa_fmcalias_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .mldsa_fmcalias_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);
    Ok(())
}

// ROM Verification Environment
pub(crate) struct FakeRomImageVerificationEnv<'a, 'b> {
    pub(crate) sha256: &'a mut Sha256,
    pub(crate) sha2_512_384: &'a mut Sha2_512_384,
    pub(crate) sha2_512_384_acc: &'a mut Sha2_512_384Acc,
    pub(crate) soc_ifc: &'a mut SocIfc,
    pub(crate) data_vault: &'a DataVault,
    pub(crate) ecc384: &'a mut Ecc384,
    pub(crate) mldsa87: &'a mut Mldsa87,
    pub image: &'b [u8],
    pub(crate) dma: &'a Dma,
}

impl ImageVerificationEnv for &mut FakeRomImageVerificationEnv<'_, '_> {
    /// Calculate 384 digest using SHA2 Engine
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest384> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = self
            .image
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(self.sha2_512_384.sha384_digest(data)?.0)
    }

    /// Calculate 512 digest using SHA2 Engine
    fn sha512_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest512> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = self
            .image
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(self.sha2_512_384.sha512_digest(data)?.0)
    }

    fn sha384_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest384> {
        let mut digest = Array4x12::default();

        if let Some(mut sha_acc_op) = self
            .sha2_512_384_acc
            .try_start_operation(ShaAccLockState::NotAcquired)?
        {
            sha_acc_op
                .digest_384(len, offset, false, &mut digest)
                .map_err(|_| digest_failure)?;
        } else {
            Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
        };

        Ok(digest.0)
    }

    fn sha512_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest512> {
        let mut digest = Array4x16::default();

        if let Some(mut sha_acc_op) = self
            .sha2_512_384_acc
            .try_start_operation(ShaAccLockState::NotAcquired)?
        {
            sha_acc_op
                .digest_512(len, offset, false, &mut digest)
                .map_err(|_| digest_failure)?;
        } else {
            Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
        };

        Ok(digest.0)
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Array4xN<12, 48>> {
        if self.soc_ifc.verify_in_fake_mode() {
            let pub_key = Ecc384PubKey {
                x: pub_key.x.into(),
                y: pub_key.y.into(),
            };

            let digest: Array4x12 = digest.into();

            let sig = Ecc384Signature {
                r: sig.r.into(),
                s: sig.s.into(),
            };

            self.ecc384.verify_r(&pub_key, &digest, &sig)
        } else {
            // Mock verify, just always return success
            Ok(Array4x12::from(sig.r))
        }
    }

    fn lms_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        if self.soc_ifc.verify_in_fake_mode() {
            let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
            for i in 0..digest.len() {
                message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
            }
            Lms::default().verify_lms_signature_cfi(self.sha256, &message, pub_key, sig)
        } else {
            // Mock verify, just always return success
            Ok(HashValue::from(pub_key.digest))
        }
    }

    fn mldsa87_verify(
        &mut self,
        msg: &[u8],
        pub_key: &ImageMldsaPubKey,
        sig: &ImageMldsaSignature,
    ) -> CaliptraResult<Mldsa87Result> {
        if self.soc_ifc.verify_in_fake_mode() {
            let pub_key = Mldsa87PubKey::from(pub_key.0);
            let sig = Mldsa87Signature::from(sig.0);

            self.mldsa87.verify_var(&pub_key, &msg, &sig)
        } else {
            // Mock verify, just always return success
            Ok(Mldsa87Result::Success)
        }
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_info_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().vendor_pub_key_info_hash().into()
    }

    /// Retrieve Vendor ECC Public Key Revocation Bitmask
    fn vendor_ecc_pub_key_revocation(&self) -> VendorEccPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation()
    }

    /// Retrieve Vendor LMS Public Key Revocation Bitmask
    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_lms_pub_key_revocation()
    }

    /// Retrieve Vendor MLDSA Public Key Revocation Bitmask
    fn vendor_mldsa_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_mldsa_pub_key_revocation()
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().owner_pub_key_hash().into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.soc_ifc.fuse_bank().anti_rollback_disable()
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.soc_ifc.lifecycle()
    }

    /// Get the vendor ECC key index saved in data vault on cold boot
    fn vendor_ecc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.vendor_ecc_pk_index()
    }

    /// Get the vendor LMS key index saved in data vault on cold boot
    fn vendor_pqc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.vendor_pqc_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.fmc_tci().into()
    }

    // Get Fuse FW Manifest SVN
    fn fw_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fw_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        caliptra_common::memory_layout::ICCM_RANGE
    }

    fn set_fw_extended_error(&mut self, err: u32) {
        self.soc_ifc.set_fw_extended_error(err);
    }

    fn pqc_key_type_fuse(&self) -> CaliptraResult<FwVerificationPqcKeyType> {
        let pqc_key_type =
            FwVerificationPqcKeyType::from_u8(self.soc_ifc.fuse_bank().pqc_key_type() as u8)
                .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_INVALID_PQC_KEY_TYPE_IN_FUSE)?;
        Ok(pqc_key_type)
    }
}
