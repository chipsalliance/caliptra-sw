/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    File contains the entry point for build time script used for generating various X509 artifacts
    used by Caliptra Firmware.

--*/

mod cert;
mod code_gen;
mod csr;
mod tbs;
mod x509;

use code_gen::CodeGen;
use x509::{EcdsaSha384Algo, Fwid, FwidParam, KeyUsage};

use std::env;

// Main Entry point
fn main() {
    let out_dir_os_str = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir_os_str.to_str().unwrap();

    gen_init_devid_csr(out_dir);
    gen_local_devid_cert(out_dir);
    gen_fmc_alias_cert(out_dir);
    gen_rt_alias_cert(out_dir);
}

/// Generated Initial DeviceId Cert Signing request Template
fn gen_init_devid_csr(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 1.0 IDevID");
    CodeGen::gen_code("InitDevIdCsrTbs", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
fn gen_local_devid_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 1.0 LDevID", "Caliptra 1.0 IDevID");
    CodeGen::gen_code("LocalDevIdCertTbs", template, out_dir);
}

fn gen_fmc_alias_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*fmc_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_FMC_TCI",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xCD; 48],
                },
            }],
        );
    let template = bldr.tbs_template("Caliptra 1.0 FMC Alias", "Caliptra 1.0 LDevID");
    CodeGen::gen_code("FmcAliasCertTbs", template, out_dir);
}

fn gen_rt_alias_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    // Add KeyCertSign to allow signing of other certs
    usage.set_key_cert_sign(true);
    // Add DigitalSignature to allow signing of firmware
    usage.set_digital_signature(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
        // Basic Constraints : CA = true, PathLen = 2
        .add_basic_constraints_ext(true, 2)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template("Caliptra 1.0 Rt Alias", "Caliptra 1.0 FMC Alias");
    CodeGen::gen_code("RtAliasCertTbs", template, out_dir);
}
