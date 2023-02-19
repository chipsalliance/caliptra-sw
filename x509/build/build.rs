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
use x509::{EcdsaSha384Algo, KeyUsage};

use std::env;

// Main Entry point
fn main() {
    let out_dir_os_str = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir_os_str.to_str().unwrap();

    gen_init_devid_csr(out_dir);
    gen_local_devid_cert(out_dir);
}

/// Generated Initial DeviceId Cert Signing request Template
fn gen_init_devid_csr(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 0)
        .add_key_usage_ext(usage)
        .add_dev_sn_ext(&[0xFF; 8]);
    let template = bldr.tbs_template("Caliptra IDevID");
    CodeGen::gen_code("InitDevIdCsr", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
fn gen_local_devid_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 0)
        .add_key_usage_ext(usage)
        .add_dev_sn_ext(&[0xFF; 8]);
    let template = bldr.tbs_template("Caliptra LDevID", "Caliptra IDevID");
    CodeGen::gen_code("LocalDevIdCert", template, out_dir);
}
