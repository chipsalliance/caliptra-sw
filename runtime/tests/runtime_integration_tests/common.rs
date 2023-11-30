// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{self, APP_WITH_UART, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
    x509::{X509Name, X509NameBuilder},
};

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(
    test_fwid: Option<&'static FwId>,
    test_image_options: Option<ImageOptions>,
    init_params: Option<InitParams>,
) -> DefaultHwModel {
    let runtime_fwid = test_fwid.unwrap_or(&APP_WITH_UART);

    let image_options = test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = 0xaaaaaaaa;
        opts.app_version = 0xbbbbbbbb;
        opts
    });

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let init_params = match init_params {
        Some(init_params) => init_params,
        None => InitParams {
            rom: &rom,
            ..Default::default()
        },
    };

    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, runtime_fwid, image_options)
        .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params,
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}

pub fn generate_test_x509_cert(ec_key: PKey<Private>) -> X509 {
    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    let mut subj_name_builder = X509Name::builder().unwrap();
    subj_name_builder
        .append_entry_by_text("CN", "example.com")
        .unwrap();
    let subject_name = X509NameBuilder::build(subj_name_builder);
    cert_builder.set_subject_name(&subject_name).unwrap();
    cert_builder.set_issuer_name(&subject_name).unwrap();
    cert_builder.set_pubkey(&ec_key).unwrap();
    cert_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    cert_builder.sign(&ec_key, MessageDigest::sha384()).unwrap();
    cert_builder.build()
}
