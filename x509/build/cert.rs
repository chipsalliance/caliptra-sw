/*++

Licensed under the Apache-2.0 license.

File Name:

    cert.rs

Abstract:

    File contains generation of X509 Certificate To Be Singed (TBS) template that can be
    substituted at firmware runtime.

--*/

use crate::tbs::{TbsParam, TbsTemplate};
use crate::x509::{self, AsymKey, KeyUsage, SigningAlgorithm};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::stack::Stack;
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

/// Certificate Template Param
struct CertTemplateParam {
    tbs_param: TbsParam,
    needle: Vec<u8>,
}

/// Certificate Template Builder
pub struct CertTemplateBuilder<Algo: SigningAlgorithm> {
    algo: Algo,
    builder: X509Builder,
    exts: Stack<X509Extension>,
    params: Vec<CertTemplateParam>,
}

impl<Algo: SigningAlgorithm> CertTemplateBuilder<Algo> {
    // Create an instance of `CertificateTemplateBuilder`
    pub fn new() -> Self {
        Self {
            algo: Algo::default(),
            builder: X509Builder::new().unwrap(),
            exts: Stack::new().unwrap(),
            params: vec![],
        }
    }

    /// Add X509 Basic Constraints Extension
    ///
    /// # Arguments
    ///
    /// * `ca`       - Flag indicating if the certificate is a Certificate Authority
    /// * `path_len` - Certificate path length
    pub fn add_basic_constraints_ext(mut self, ca: bool, path_len: u32) -> Self {
        self.exts
            .push(x509::make_basic_constraints_ext(ca, path_len))
            .unwrap();
        self
    }

    /// Add X509 Key Usage Extension
    ///
    /// # Arguments
    ///
    /// * `usage` - Key Usage
    pub fn add_key_usage_ext(mut self, usage: KeyUsage) -> Self {
        self.exts.push(x509::make_key_usage_ext(usage)).unwrap();
        self
    }

    /// Add Device Serial Number Extension
    ///
    /// # Arguments
    ///
    /// * `sn` - Device Serial Number
    pub fn add_dev_sn_ext(mut self, sn: &[u8]) -> Self {
        self.exts.push(x509::make_tcg_ueid_ext(sn)).unwrap();

        let param = CertTemplateParam {
            tbs_param: TbsParam::new("DEVICE_SERIAL_NUMBER", 0, sn.len()),
            needle: sn.to_vec(),
        };
        self.params.push(param);

        self
    }

    /// Add Subject Key Id Extension
    ///
    /// # Arguments
    ///
    /// * `key_id` - Key Id
    fn add_subj_key_id_ext(&mut self, key_id: &[u8]) {
        self.exts
            .push(x509::make_subj_key_id_ext(
                &self.builder.x509v3_context(None, None),
            ))
            .unwrap();

        let param = CertTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_KEY_ID", 0, key_id.len()),
            needle: key_id.to_vec(),
        };
        self.params.push(param);
    }

    /// Add Authority Key Id Extension
    ///
    /// # Arguments
    ///
    /// * `key_id` - Key Id
    fn add_auth_key_id_ext(&mut self, key_id: &[u8]) {
        self.exts.push(x509::make_auth_key_id_ext(key_id)).unwrap();

        let param = CertTemplateParam {
            tbs_param: TbsParam::new("AUTHORITY_KEY_ID", 0, key_id.len()),
            needle: key_id.to_vec(),
        };
        self.params.push(param);
    }

    /// Generate To Be Signed (TBS) Template
    pub fn tbs_template(mut self) -> TbsTemplate {
        // Generate key pair
        let subject_key = self.algo.gen_key();
        let issuer_key = self.algo.gen_key();

        // Set Version
        self.builder.set_version(2).unwrap();

        // Set the valid from time
        let valid_from = Asn1Time::from_str("20230101000000Z").unwrap();
        self.builder.set_not_before(&valid_from).unwrap();

        // Set the valid to time
        let valid_to = Asn1Time::from_str("99991231235959Z").unwrap();
        self.builder.set_not_after(&valid_to).unwrap();

        // Set the serial number
        let serial_number_bytes = [0x7Fu8; 20];
        let serial_number = BigNum::from_slice(&serial_number_bytes).unwrap();
        let serial_number = serial_number.to_asn1_integer().unwrap();
        self.builder.set_serial_number(&serial_number).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("SERIAL_NUMBER", 0, serial_number_bytes.len()),
            needle: serial_number_bytes.to_vec(),
        };
        self.params.push(param);

        // Set Subject Public Key
        self.builder.set_pubkey(subject_key.priv_key()).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("PUBLIC_KEY", 0, subject_key.pub_key().len()),
            needle: subject_key.pub_key().to_vec(),
        };
        self.params.push(param);

        // Set the subject name
        let mut subject_name = X509NameBuilder::new().unwrap();
        subject_name
            .append_entry_by_text("CN", &subject_key.hex_str())
            .unwrap();
        let subject_name = subject_name.build();
        self.builder.set_subject_name(&subject_name).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_NAME", 0, subject_key.hex_str().len()),
            needle: subject_key.hex_str().into_bytes(),
        };
        self.params.push(param);

        // Set the issuer name
        let mut issuer_name = X509NameBuilder::new().unwrap();
        issuer_name
            .append_entry_by_text("CN", &issuer_key.hex_str())
            .unwrap();
        let issuer_name = issuer_name.build();
        self.builder.set_issuer_name(&issuer_name).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("ISSUER_NAME", 0, issuer_key.hex_str().len()),
            needle: issuer_key.hex_str().into_bytes(),
        };
        self.params.push(param);

        // Add Subject Key Identifier
        self.add_subj_key_id_ext(&subject_key.sha1());

        // Add Authority Key Identifier
        self.add_auth_key_id_ext(&issuer_key.sha1());

        // Add the requested extensions
        for ext in self.exts {
            self.builder.append_extension(ext).unwrap();
        }

        // Sign the Certificate
        self.builder
            .sign(subject_key.priv_key(), self.algo.digest())
            .unwrap();

        // Generate the Certificate
        let cert = self.builder.build();

        // Serialize the Certificate to DER
        let der = cert.to_der().unwrap();

        // Retrieve the To be signed portion from the Certificate
        let mut tbs = x509::get_tbs(der);

        // Calculate the offset of parameters and sanitize the TBS section
        let params = self
            .params
            .iter()
            .map(|p| x509::sanitize(x509::init_param(&p.needle, &tbs, p.tbs_param), &mut tbs))
            .collect();

        // Create the template
        TbsTemplate::new(tbs, params)
    }
}
