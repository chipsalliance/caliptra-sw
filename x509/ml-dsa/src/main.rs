/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

--*/
mod cert_rustcrypto;
mod code_gen;
mod csr_rustcrypto;
mod tbs;

// Main Entry point
fn main() {
    // Get the output directory from environment
    let out_dir_os_str = std::env::var_os("OUT_DIR").unwrap_or_else(|| {
        eprintln!("OUT_DIR environment variable not set, using temp dir");
        std::env::temp_dir().into()
    });
    let out_dir = out_dir_os_str.to_str().unwrap();

    // Generate all certificate and CSR templates
    gen_init_devid_csr_mldsa87(out_dir);
    gen_fmc_alias_csr_mldsa87(out_dir);
    gen_local_devid_cert_mldsa87(out_dir);
    gen_fmc_alias_cert_mldsa87(out_dir);
    gen_rt_alias_cert_mldsa87(out_dir);
}

/// Generated Initial DeviceId Cert Signing request Template
fn gen_init_devid_csr_mldsa87(out_dir: &str) {
    use crate::code_gen::CodeGen;
    use crate::csr_rustcrypto::CsrTemplateBuilder;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Set up key usage for certificate signing
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 IDevID");

    // Generate code from the template
    CodeGen::gen_code("InitDevIdCsrTbsMlDsa87", template, out_dir);
}

/// Generate FMC Alias CSR Template
fn gen_fmc_alias_csr_mldsa87(out_dir: &str) {
    use crate::code_gen::CodeGen;
    use crate::csr_rustcrypto::CsrTemplateBuilder;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Set up key usage for certificate signing
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 FMC Alias");

    // Generate code from the template
    CodeGen::gen_code("FmcAliasTbsMlDsa87", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
fn gen_local_devid_cert_mldsa87(out_dir: &str) {
    use crate::cert_rustcrypto::CertTemplateBuilder;
    use crate::code_gen::CodeGen;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Build the FMC Alias certificate template
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17]);

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 LDevID", "Caliptra 2.0 MlDsa87 IDevID");

    // Generate the code
    CodeGen::gen_code("LocalDevIdCertTbsMlDsa87", template, out_dir);
}

/// Generate FMC Alias Certificate Template
fn gen_fmc_alias_cert_mldsa87(out_dir: &str) {
    use crate::cert_rustcrypto::{CertTemplateBuilder, Fwid, FwidParam};
    use crate::code_gen::CodeGen;
    use const_oid::ObjectIdentifier;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // SHA-384 OID
    let sha384_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

    // Create long-lived FWID parameters
    let device_fwids = [FwidParam {
        name: "TCB_INFO_DEVICE_INFO_HASH",
        fwid: Fwid {
            hash_alg: sha384_oid,
            digest: &[0xEF; 48],
        },
    }];

    let fmc_fwids = [FwidParam {
        name: "TCB_INFO_FMC_TCI",
        fwid: Fwid {
            hash_alg: sha384_oid,
            digest: &[0xCD; 48],
        },
    }];

    // Build the FMC Alias certificate template with TCB info
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &device_fwids,
            /*fmc_fwids=*/
            &fmc_fwids,
        );

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template(
        "Caliptra 2.0 MlDsa87 FMC Alias",
        "Caliptra 2.0 MlDsa87 LDevID",
    );

    // Generate the code
    CodeGen::gen_code("FmcAliasCertTbsMlDsa87", template, out_dir);
}

/// Generate RT Alias Certificate Template
fn gen_rt_alias_cert_mldsa87(out_dir: &str) {
    use crate::cert_rustcrypto::{CertTemplateBuilder, Fwid, FwidParam};
    use crate::code_gen::CodeGen;
    use const_oid::ObjectIdentifier;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create KeyUsage with key_cert_sign set to true and digital_signature set to true
    let key_usage = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::DigitalSignature);

    // SHA-384 OID
    let sha384_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

    // Create RT FWID parameter
    let rt_fwids = [FwidParam {
        name: "TCB_INFO_RT_TCI",
        fwid: Fwid {
            hash_alg: sha384_oid,
            digest: &[0xCD; 48],
        },
    }];

    // Build the RT Alias certificate template with TCB info
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 2)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_rt_dice_tcb_info_ext(0xC4, &rt_fwids);

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template(
        "Caliptra 2.0 MlDsa87 RT Alias",
        "Caliptra 2.0 MlDsa87 FMC Alias",
    );

    // Generate the code
    CodeGen::gen_code("RtAliasCertTbsMlDsa87", template, out_dir);
}
