// Licensed under the Apache-2.0 license

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use crate::test_activate_firmware::TEST_SRAM_BASE;
use caliptra_api::{
    mailbox::{
        CmHashAlgorithm, CmShaDmaReq, CmShaDmaResp, CommandId, MailboxReq, MailboxReqHeader,
        MailboxRespHeader, MailboxRespHeaderVarSize, ResponseVarSize,
    },
    SocManager,
};
use caliptra_builder::ImageOptions;
use caliptra_common::checksum::{calc_checksum, verify_checksum};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use sha2::{Digest, Sha384, Sha512};
use zerocopy::IntoBytes;

const ALGORITHMS: [CmHashAlgorithm; 2] = [CmHashAlgorithm::Sha384, CmHashAlgorithm::Sha512];
// Past the default MCU firmware at the start of MCU SRAM.
const STAGING_OFFSET: usize = 0x1000;
// Caliptra's AXI aperture: its size and the offsets of the SHA accelerator
// registers and the mailbox SRAM.
const APERTURE_SIZE: u64 = 0x8_0000;
const SHA_ACC_OFFSET: u64 = 0x2_1000;
const MBOX_SRAM_OFFSET: u64 = 0x4_0000;

fn subsystem_model() -> DefaultHwModel {
    run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    })
}

fn request(algorithm: CmHashAlgorithm, axi_addr: u64, length: u32) -> CmShaDmaReq {
    CmShaDmaReq {
        hash_algorithm: algorithm.into(),
        axi_addr_lo: axi_addr as u32,
        axi_addr_hi: (axi_addr >> 32) as u32,
        length,
        ..Default::default()
    }
}

fn cm_sha_dma(model: &mut DefaultHwModel, req: CmShaDmaReq) -> Result<Vec<u8>, ModelError> {
    let mut cmd = MailboxReq::CmShaDma(req);
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(CommandId::CM_SHA_DMA.into(), cmd.as_bytes().unwrap())
        .map(|resp| resp.expect("CM_SHA_DMA should return a response"))
}

fn expected_digest(algorithm: CmHashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        CmHashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        CmHashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        CmHashAlgorithm::Reserved => unreachable!(),
    }
}

fn assert_digest(
    model: &mut DefaultHwModel,
    algorithm: CmHashAlgorithm,
    axi_addr: u64,
    data: &[u8],
) {
    let expected = expected_digest(algorithm, data);
    let bytes = cm_sha_dma(model, request(algorithm, axi_addr, data.len() as u32)).unwrap();
    assert_eq!(
        bytes.len(),
        size_of::<MailboxRespHeaderVarSize>() + expected.len()
    );

    let mut resp = CmShaDmaResp::default();
    resp.as_mut_bytes()[..bytes.len()].copy_from_slice(&bytes);
    assert!(verify_checksum(resp.hdr.hdr.chksum, 0, &bytes[4..]));
    assert_eq!(
        resp.hdr.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(resp.hdr.data_len as usize, expected.len());
    assert_eq!(resp.data().unwrap(), &expected[..]);
}

fn assert_rejected(model: &mut DefaultHwModel, req: CmShaDmaReq, expected: CaliptraError) {
    let err = cm_sha_dma(model, req).unwrap_err();
    assert_error(model, expected, err);
}

fn assert_raw_rejected(model: &mut DefaultHwModel, raw: &[u8], expected: CaliptraError) {
    let err = model
        .mailbox_execute(CommandId::CM_SHA_DMA.into(), raw)
        .unwrap_err();
    assert_error(model, expected, err);
}

fn request_bytes(data: &[u8]) -> Vec<u8> {
    let header = MailboxReqHeader {
        chksum: calc_checksum(CommandId::CM_SHA_DMA.into(), data),
    };
    let mut raw = header.as_bytes().to_vec();
    raw.extend_from_slice(data);
    raw
}

fn payload(req: &CmShaDmaReq) -> Vec<u8> {
    req.as_bytes()[size_of::<MailboxReqHeader>()..].to_vec()
}

fn caliptra_base(model: &mut DefaultHwModel) -> u64 {
    let soc_ifc = model.soc_ifc();
    (u64::from(soc_ifc.ss_caliptra_base_addr_h().read()) << 32)
        | u64::from(soc_ifc.ss_caliptra_base_addr_l().read())
}

fn staged_data(model: &mut DefaultHwModel) -> (u64, Vec<u8>) {
    // Ends in a partial 128-byte block.
    let data: Vec<u8> = (0..0x404).map(|i| i as u8).collect();
    let axi_addr = model
        .write_payload_to_ss_staging_area(&data, STAGING_OFFSET)
        .unwrap();
    (axi_addr, data)
}

fn check_staged_digest(algorithm: CmHashAlgorithm) {
    let mut model = subsystem_model();
    let (axi_addr, data) = staged_data(&mut model);

    assert_digest(&mut model, algorithm, axi_addr, &data);
    // A second request succeeds only if the first released the accelerator.
    let resp = model
        .mailbox_execute_req(request(algorithm, axi_addr, data.len() as u32))
        .unwrap();
    assert_eq!(resp.data().unwrap(), &expected_digest(algorithm, &data)[..]);
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_sha384() {
    check_staged_digest(CmHashAlgorithm::Sha384);
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_sha512() {
    check_staged_digest(CmHashAlgorithm::Sha512);
}

// Spans three DMA transfers (1 MiB, 1 MiB, remainder) from an offset start.
// test_sram exists only in the emulator.
#[cfg_attr(
    any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    ),
    ignore
)]
#[test]
fn test_cm_sha_dma_larger_than_1mib() {
    const OFFSET: usize = 4;
    const LEN: usize = 2 * 1024 * 1024 + 3 * 1024;
    // A prime period, so every 1 MiB chunk holds different data.
    let sram: Vec<u8> = (0..OFFSET + LEN).map(|i| (i % 251) as u8).collect();
    let mut model = run_rt_test(RuntimeTestArgs {
        test_sram: Some(&sram),
        subsystem_mode: true,
        ..Default::default()
    });
    let axi_addr =
        ((u64::from(TEST_SRAM_BASE.hi) << 32) | u64::from(TEST_SRAM_BASE.lo)) + OFFSET as u64;

    for algorithm in ALGORITHMS {
        assert_digest(&mut model, algorithm, axi_addr, &sram[OFFSET..]);
    }
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_zero_length() {
    let mut model = subsystem_model();
    let axi_addr = model.staging_physical_address().unwrap();
    for algorithm in ALGORITHMS {
        assert_rejected(
            &mut model,
            request(algorithm, axi_addr, 0),
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_unaligned() {
    let mut model = subsystem_model();
    let axi_addr = model.staging_physical_address().unwrap();
    for (addr, length) in [(axi_addr + 2, 64), (axi_addr, 65)] {
        assert_rejected(
            &mut model,
            request(CmHashAlgorithm::Sha384, addr, length),
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_unknown_algorithm() {
    let mut model = subsystem_model();
    let axi_addr = model.staging_physical_address().unwrap();
    for hash_algorithm in [0, 3] {
        let req = CmShaDmaReq {
            hash_algorithm,
            ..request(CmHashAlgorithm::Sha384, axi_addr, 64)
        };
        assert_rejected(
            &mut model,
            req,
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_nonzero_flags() {
    let mut model = subsystem_model();
    let axi_addr = model.staging_physical_address().unwrap();
    let req = CmShaDmaReq {
        flags: 1,
        ..request(CmHashAlgorithm::Sha384, axi_addr, 64)
    };
    assert_rejected(
        &mut model,
        req,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
    );
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_bad_size() {
    let mut model = subsystem_model();
    let axi_addr = model.staging_physical_address().unwrap();
    let mut bytes = payload(&request(CmHashAlgorithm::Sha384, axi_addr, 64));
    bytes.extend_from_slice(&[0; 4]);
    for len in [0, bytes.len() - 8, bytes.len()] {
        assert_raw_rejected(
            &mut model,
            &request_bytes(&bytes[..len]),
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_invalid_checksum() {
    let mut model = subsystem_model();
    let axi_addr = model.staging_physical_address().unwrap();
    let mut raw = request_bytes(&payload(&request(CmHashAlgorithm::Sha384, axi_addr, 64)));
    raw[0] ^= 1;
    assert_raw_rejected(&mut model, &raw, CaliptraError::RUNTIME_INVALID_CHECKSUM);
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_4gib_crossing() {
    let mut model = subsystem_model();
    for axi_addr in [0xFFFF_F000, 0xFFFF_FFFF_FFFF_F000] {
        assert_rejected(
            &mut model,
            request(CmHashAlgorithm::Sha512, axi_addr, 0x2000),
            CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        );
    }
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_caliptra_aperture() {
    let mut model = subsystem_model();
    let base = caliptra_base(&mut model);
    assert!(base as u32 >= 4, "base - 4 would cross a 4 GiB boundary");
    for (axi_addr, length) in [
        (base + SHA_ACC_OFFSET, 64),
        (base + MBOX_SRAM_OFFSET, 4),
        (base + APERTURE_SIZE - 4, 4),
        (base - 4, 8),
    ] {
        assert_rejected(
            &mut model,
            request(CmHashAlgorithm::Sha384, axi_addr, length),
            CaliptraError::RUNTIME_CM_SHA_DMA_RANGE_NOT_ALLOWED,
        );
    }

    // The rejections left the SHA accelerator unlocked.
    let (axi_addr, data) = staged_data(&mut model);
    assert_digest(&mut model, CmHashAlgorithm::Sha384, axi_addr, &data);
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_key_release_window() {
    let mut model = subsystem_model();
    let soc_ifc = model.soc_ifc();
    let base = (u64::from(soc_ifc.ss_key_release_base_addr_h().read()) << 32)
        | u64::from(soc_ifc.ss_key_release_base_addr_l().read());
    let size = u32::from(soc_ifc.ss_key_release_size().read());
    // The emulator always straps a window; FPGA bitstreams may not.
    if size == 0 && cfg!(feature = "fpga_subsystem") {
        return;
    }
    assert_rejected(
        &mut model,
        request(CmHashAlgorithm::Sha384, base, 4),
        CaliptraError::RUNTIME_CM_SHA_DMA_RANGE_NOT_ALLOWED,
    );
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_cm_sha_dma_rejects_pl1() {
    let mut image_options = ImageOptions::default();
    image_options.vendor_config.pl0_pauser = None;
    let mut model = run_rt_test(RuntimeTestArgs {
        test_image_options: Some(image_options),
        subsystem_mode: true,
        ..Default::default()
    });
    let axi_addr = model.staging_physical_address().unwrap();
    assert_rejected(
        &mut model,
        request(CmHashAlgorithm::Sha384, axi_addr, 64),
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
    );
}

#[cfg_attr(feature = "fpga_subsystem", ignore)]
#[test]
fn test_cm_sha_dma_rejects_passive_mode() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: false,
        ..Default::default()
    });
    assert_rejected(
        &mut model,
        request(CmHashAlgorithm::Sha384, 0x1000, 64),
        CaliptraError::RUNTIME_CM_SHA_DMA_NOT_SUBSYSTEM_MODE,
    );
}
