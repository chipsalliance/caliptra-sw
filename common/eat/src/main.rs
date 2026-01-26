// Licensed under the Apache-2.0 license

// main.rs can use std
#[cfg(feature = "std")]
use std::error::Error;
#[cfg(feature = "std")]
use std::fs::{create_dir_all, File};
#[cfg(feature = "std")]
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;

// Use the ocp_eat library (defined in lib.rs) instead of recompiling modules
use ocp_eat::{
    cbor_tags, header_params, CborEncoder, CoseHeaderPair, CoseSign1, EatError, ProtectedHeader,
};

#[cfg(feature = "crypto")]
use ocp_eat::ocp_profile::{
    ClassMap, ConciseEvidence, ConciseEvidenceMap, DebugStatus, DigestEntry, EnvironmentMap,
    EvTriplesMap, EvidenceTripleRecord, MeasurementFormat, MeasurementMap, MeasurementValue,
    OcpEatClaims, TaggedConciseEvidence,
};

// Cryptographic imports for signature generation (only available with crypto feature)
#[cfg(feature = "crypto")]
use ecdsa::{signature::Signer, Signature, SigningKey};
#[cfg(feature = "crypto")]
use p384::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(feature = "crypto")]
use p384::{PublicKey, SecretKey};
#[cfg(feature = "crypto")]
use rand::rngs::OsRng;

// Structure to hold signing keys and certificate (only with crypto feature)
#[cfg(feature = "crypto")]
pub struct DeviceKey {
    pub signing_key: SigningKey<p384::NistP384>,
    pub public_key: PublicKey,
    pub cert_chain: Vec<u8>,
}

#[cfg(feature = "crypto")]
impl DeviceKey {
    // Generate a new device key pair with mock certificate
    pub fn generate() -> Result<Self, Box<dyn Error>> {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(secret_key);
        let public_key = PublicKey::from(signing_key.verifying_key());

        // Generate a mock certificate chain (in real usage, this would be a proper X.509 certificate)
        let cert_chain = Self::generate_mock_cert_chain(&public_key);

        Ok(DeviceKey {
            signing_key,
            public_key,
            cert_chain,
        })
    }

    // Generate a parseable certificate based on OpenSSL template
    fn generate_mock_cert_chain(public_key: &PublicKey) -> Vec<u8> {
        // Get the public key in uncompressed format (97 bytes for P-384)
        let pubkey_point = public_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_point.as_bytes();

        // Use a template based on a valid OpenSSL-generated certificate structure
        // This creates a certificate that can be parsed (but has a mock signature)
        let mut cert = vec![
            // Certificate SEQUENCE (outer container)
            0x30, 0x82, 0x02, 0x0d, // SEQUENCE (525 bytes total)
            // TBSCertificate SEQUENCE
            0x30, 0x82, 0x01, 0x92, // SEQUENCE (402 bytes)
            // Version [0] EXPLICIT (v3)
            0xa0, 0x03, 0x02, 0x01, 0x02, // Serial Number (20 bytes - from real cert)
            0x02, 0x14, 0x40, 0xea, 0x74, 0x7c, 0x71, 0x80, 0xf9, 0xc9, 0x31, 0xdd, 0xe7, 0x94,
            0x6c, 0x15, 0x17, 0xde, 0x0e, 0x14, 0xcb, 0x3e,
            // Signature Algorithm Identifier
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
            0x02, // ecdsa-with-SHA256 (changed from SHA384 to match OpenSSL)
            // Issuer Name: C=US, O=Example Corp, CN=Device Att Key
            0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53, // C=US
            0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x45, 0x78, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x72, 0x70, // O=Example Corp
            0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x44, 0x65, 0x76,
            0x69, 0x63, 0x65, 0x20, 0x41, 0x74, 0x74, 0x20, 0x4b, 0x65,
            0x79, // CN=Device Att Key
            // Validity (using current time format from OpenSSL)
            0x30, 0x1e, 0x17, 0x0d, // UTCTime
            0x32, 0x35, 0x30, 0x39, 0x31, 0x38, 0x30, 0x37, 0x30, 0x36, 0x30, 0x35,
            0x5a, // 250918070605Z (valid from)
            0x17, 0x0d, // UTCTime
            0x32, 0x36, 0x30, 0x39, 0x31, 0x38, 0x30, 0x37, 0x30, 0x36, 0x30, 0x35,
            0x5a, // 260918070605Z (valid to)
            // Subject (same as issuer for self-signed)
            0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53, // C=US
            0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x45, 0x78, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x72, 0x70, // O=Example Corp
            0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x44, 0x65, 0x76,
            0x69, 0x63, 0x65, 0x20, 0x41, 0x74, 0x74, 0x20, 0x4b, 0x65,
            0x79, // CN=Device Att Key
            // SubjectPublicKeyInfo
            0x30, 0x76, // SEQUENCE (118 bytes)
            0x30, 0x10, // AlgorithmIdentifier SEQUENCE
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // secp384r1 OID
            0x03, 0x62, 0x00, // BIT STRING (98 bytes: 0 unused bits + 97 key bytes)
        ];

        // Insert the actual public key
        cert.extend_from_slice(pubkey_bytes);

        // Extensions [3] EXPLICIT (based on OpenSSL structure)
        cert.extend_from_slice(&[
            0xa3, 0x53, // [3] EXPLICIT (83 bytes)
            0x30, 0x51, // SEQUENCE (81 bytes)
            // Subject Key Identifier extension
            0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, // subjectKeyIdentifier OID
            0x04, 0x16, 0x04, 0x14, // OCTET STRING (20 bytes)
            0x3a, 0x5e, 0xb7, 0x51, 0x53, 0x4f, 0x2c, 0x25, 0x9e, 0x04, 0x85, 0xad, 0xf1, 0x8e,
            0xd7, 0xe2, 0xd7, 0x10, 0xac, 0x7e, // Authority Key Identifier extension
            0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, // authorityKeyIdentifier OID
            0x04, 0x18, 0x30, 0x16, 0x80, 0x14, // OCTET STRING, SEQUENCE
            0x3a, 0x5e, 0xb7, 0x51, 0x53, 0x4f, 0x2c, 0x25, 0x9e, 0x04, 0x85, 0xad, 0xf1, 0x8e,
            0xd7, 0xe2, 0xd7, 0x10, 0xac, 0x7e,
            // Basic Constraints extension (critical, CA=TRUE)
            0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, // basicConstraints OID
            0x01, 0x01, 0xff, // BOOLEAN TRUE (critical)
            0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, // SEQUENCE, BOOLEAN TRUE (isCA)
        ]);

        // Signature Algorithm (repeated outside TBS)
        cert.extend_from_slice(&[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
            0x02, // ecdsa-with-SHA256
        ]);

        // Signature Value (mock but properly structured)
        cert.extend_from_slice(&[
            0x03, 0x69, 0x00, // BIT STRING (105 bytes: 0 unused bits + 104 signature bytes)
            0x30, 0x66, // SEQUENCE (102 bytes)
            0x02, 0x31, 0x00, // INTEGER r (49 bytes with leading zero)
            0x85, 0xf2, 0x71, 0xa4, 0x12, 0x27, 0xd2, 0xe3, 0x4f, 0x80, 0x6d, 0xeb, 0xd4, 0x41,
            0x78, 0x3b, 0x5c, 0x2f, 0x3e, 0x4a, 0x58, 0x92, 0x5a, 0x7d, 0xd1, 0x2c, 0x8f, 0x91,
            0x43, 0xb2, 0xe9, 0xfa, 0x6c, 0x88, 0xa1, 0x7b, 0x25, 0x4e, 0xd8, 0x9b, 0x73, 0x11,
            0x45, 0x22, 0x8f, 0x6a, 0x33, 0x44, 0x02, 0x31,
            0x00, // INTEGER s (49 bytes with leading zero)
            0xa7, 0x89, 0x4c, 0x23, 0xe1, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ]);

        cert
    }

    // Sign data using ECDSA with P-384 and SHA-384
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Create signature using ECDSA
        let signature: Signature<p384::NistP384> = self.signing_key.sign(data);

        // Convert to DER format (as expected by COSE)
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

// Function to decode CBOR files using the Python decoder
fn decode_cbor_file(cbor_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;
    use std::process::Command;

    // Check if the CBOR file exists
    if !Path::new(cbor_file_path).exists() {
        return Err(format!("CBOR file not found: {}", cbor_file_path).into());
    }

    // Check if decode.py exists in the decoder/ subdirectory
    let decoder_script = "decoder/decode.py";
    if !Path::new(decoder_script).exists() {
        return Err(format!("Python decoder script not found: {}", decoder_script).into());
    }

    println!("=== Decoding CBOR Token ===");
    println!("File: {}", cbor_file_path);
    println!("Using decoder: {}", decoder_script);
    println!();

    // Execute the Python decoder
    let output = Command::new("python3")
        .arg(decoder_script)
        .arg(cbor_file_path)
        .output()?;

    // Print the decoder output
    if !output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    if !output.stderr.is_empty() {
        eprintln!(
            "Decoder stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    if !output.status.success() {
        return Err(format!(
            "Python decoder failed with exit code: {:?}",
            output.status.code()
        )
        .into());
    }

    Ok(())
}

// Modified implementation of create_example_eat that generates signature internally
#[cfg(feature = "crypto")]
pub fn create_example_eat(
    buffer: &mut [u8],
    issuer: &str,
    concise_evidence: &ConciseEvidence,
    device_key: &DeviceKey,
) -> Result<usize, EatError> {
    let cti = [0x01; 16];
    let nonce = [0x02; 16];
    let measurement = MeasurementFormat::new(concise_evidence);
    let measurements_array = [measurement];

    let mut claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements_array);
    claims.issuer = Some(issuer);
    claims.cti = Some(&cti);

    // Use P-384 (ES384) for our P-384 key
    let protected_header = ProtectedHeader::new_es384();
    let x5chain_header = CoseHeaderPair {
        key: header_params::X5CHAIN,
        value: &device_key.cert_chain,
    };
    let unprotected_headers = [x5chain_header];

    // Encode payload (claims)
    const MAX_PAYLOAD_SIZE: usize = 8192;
    let mut payload_buffer = [0u8; MAX_PAYLOAD_SIZE];
    let mut evidence_scratch_buf = [0u8; 1024];
    let payload_len = {
        let mut encoder = CborEncoder::new(&mut payload_buffer);
        claims
            .encode(&mut encoder, &mut evidence_scratch_buf)
            .map_err(|_| EatError::EncodingError)?;
        encoder.len()
    };

    // Initialize COSE Sign1 encoder with protected header, unprotected headers, and payload
    let cose_sign1 = CoseSign1::new(buffer)
        .protected_header(&protected_header)
        .unprotected_headers(&unprotected_headers)
        .payload(&payload_buffer[..payload_len]);

    // Get signature context for signing
    const MAX_SIG_CONTEXT_SIZE: usize = 16384;
    let mut sig_context_buffer = [0u8; MAX_SIG_CONTEXT_SIZE];
    let sig_context_len = cose_sign1
        .get_signature_context(&mut sig_context_buffer)
        .map_err(|_| EatError::EncodingError)?;

    // Generate signature
    let signature = device_key
        .sign(&sig_context_buffer[..sig_context_len])
        .map_err(|_| EatError::EncodingError)?;

    // Complete encoding with signature and EAT tags [55799, 61] + automatic COSE_Sign1 tag [18]
    cose_sign1
        .signature(&signature)
        .encode(Some(&[cbor_tags::SELF_DESCRIBED_CBOR, cbor_tags::CWT]))
        .map_err(|_| EatError::EncodingError)
}

// Create mock structured concise evidence (similar to CBOR version but returns structured data)
fn create_mock_concise_evidence_structured() -> ConciseEvidence<'static> {
    // Static data for mock evidence
    static DIGEST_DATA: &[u8; 48] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x56,
    ];

    static RAW_VALUE_DATA: &[u8; 4] = &[0xde, 0xad, 0xbe, 0xef];

    // Firmware measurement for first environment
    static FIRMWARE_MEASUREMENT: [MeasurementMap<'static>; 1] = [MeasurementMap {
        key: 0,
        mval: MeasurementValue {
            version: Some("1.2.3"),
            svn: Some(1),
            digests: Some(&[DigestEntry {
                alg_id: 7, // SHA-384
                value: DIGEST_DATA,
            }]),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        },
    }];

    // Hardware config measurement for second environment
    static HW_CONFIG_MEASUREMENT: [MeasurementMap<'static>; 1] = [MeasurementMap {
        key: 0,
        mval: MeasurementValue {
            version: None,
            svn: None,
            digests: None,
            integrity_registers: None,
            raw_value: Some(RAW_VALUE_DATA),
            raw_value_mask: None,
        },
    }];

    // Create RATS CoRIM compliant evidence structure with 2 environments
    static ENVIRONMENT_MAP_1: EnvironmentMap<'static> = EnvironmentMap {
        class: ClassMap {
            class_id: "0x0001",
            vendor: Some("Example Corp"),
            model: Some("ExampleChip-v1.0"),
        },
    };

    static ENVIRONMENT_MAP_2: EnvironmentMap<'static> = EnvironmentMap {
        class: ClassMap {
            class_id: "0x0002",
            vendor: Some("Example Corp"),
            model: Some("ExampleChip-v1.0"),
        },
    };

    // First evidence triple: Environment 1 with firmware measurement
    static EVIDENCE_TRIPLE_1: EvidenceTripleRecord<'static> = EvidenceTripleRecord {
        environment: ENVIRONMENT_MAP_1,
        measurements: &FIRMWARE_MEASUREMENT,
    };

    // Second evidence triple: Environment 2 with hardware config measurement
    static EVIDENCE_TRIPLE_2: EvidenceTripleRecord<'static> = EvidenceTripleRecord {
        environment: ENVIRONMENT_MAP_2,
        measurements: &HW_CONFIG_MEASUREMENT,
    };
    static EV_TRIPLES_MAP: EvTriplesMap<'static> = EvTriplesMap {
        evidence_triples: Some(&[EVIDENCE_TRIPLE_1, EVIDENCE_TRIPLE_2]),
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
    };

    static CONCISE_EVIDENCE_MAP: ConciseEvidenceMap<'static> = ConciseEvidenceMap {
        ev_triples: EV_TRIPLES_MAP,
        evidence_id: None,
        profile: None,
    };

    ConciseEvidence::Tagged(TaggedConciseEvidence {
        concise_evidence: CONCISE_EVIDENCE_MAP,
    })
}

#[cfg(all(feature = "std", feature = "crypto"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Check for decode mode
    if args.len() > 1 && args[1] == "--decode" {
        if args.len() < 3 {
            println!("Usage: {} --decode <cbor_file>", args[0]);
            println!("       Decode an existing CBOR token using the Python decoder");
            println!();
            println!("Example:");
            println!("  {} --decode output/my_token.cbor", args[0]);
            println!("  {} --decode /path/to/token.cbor", args[0]);
            return Ok(());
        }

        // Call the Python decoder
        return decode_cbor_file(&args[2]);
    }

    // Generation mode (existing functionality)
    let output_file = if args.len() > 1 {
        &args[1]
    } else {
        println!("Usage: {} <output_file.cbor>", args[0]);
        println!("       {} --decode <cbor_file>", args[0]);
        println!();
        println!("Generate mode:");
        println!("  Generate an OCP EAT (Entity Attestation Token) and save to output/ folder");
        println!(
            "  <output_file.cbor>  Filename for the generated CBOR token (saved in output/ folder)"
        );
        println!();
        println!("Decode mode:");
        println!("  Decode an existing CBOR token using the Python decoder");
        println!("  --decode <cbor_file>  Path to CBOR file to decode");
        println!();
        println!("Examples:");
        println!(
            "  {} example_eat_token.cbor          # Generate output/example_eat_token.cbor",
            args[0]
        );
        println!(
            "  {} --decode output/my_token.cbor   # Decode existing token",
            args[0]
        );
        return Ok(());
    };

    println!("=== OCP EAT Encoder Example ===");
    println!("Output file: {}", output_file);

    // Generate device key pair and certificate
    println!("Generating device key pair...");
    let device_key = DeviceKey::generate()?;
    println!("✓ Device key pair generated successfully");
    println!(
        "  Public key: {:02x?}",
        &device_key.public_key.to_encoded_point(false).as_bytes()[1..9]
    );
    println!("  Certificate size: {} bytes", device_key.cert_chain.len());

    // Allocate buffer for the encoded EAT token (64KB max per OCP spec)
    let mut eat_buffer = vec![0u8; 65536];

    println!("\n=== Creating EAT Token ===");

    // Create mock concise evidence structure
    let device_evidence = create_mock_concise_evidence_structured();
    println!("Created structured concise evidence with RATS CoRIM format");

    // Create the EAT token with automatic signature generation
    println!("Encoding EAT token with structured evidence...");

    match create_example_eat(
        &mut eat_buffer,
        "CN=Example Device Attestation Key,O=Example Corp,C=US", // Issuer name
        &device_evidence,                                        // Structured evidence
        &device_key,                                             // Device key for signing
    ) {
        Ok(encoded_size) => {
            println!("✓ EAT token created successfully!");
            println!("  Encoded size: {} bytes", encoded_size);
            println!(
                "  Buffer utilization: {:.1}%",
                (encoded_size as f64 / eat_buffer.len() as f64) * 100.0
            );

            // Validate the token size is within OCP limits (64kB)
            if encoded_size <= 65536 {
                println!("✓ Token size is within OCP profile limits");
            } else {
                println!("⚠ WARNING: Token size exceeds OCP profile limits!");
            }

            // Truncate buffer to actual size
            eat_buffer.truncate(encoded_size);

            // Print first 64 bytes as hex for inspection
            println!("\nFirst 64 bytes of encoded token:");
            print_hex_dump(&eat_buffer[..std::cmp::min(64, encoded_size)]);

            // Save to file for analysis
            save_token_to_file(&eat_buffer, output_file)?;

            // Print CBOR diagnostic information
            print_cbor_diagnostic(&eat_buffer[..std::cmp::min(256, encoded_size)]);
        }
        Err(error) => {
            println!("✗ Failed to create EAT token:");
            match error {
                EatError::BufferTooSmall => {
                    println!("  Error: Buffer too small for EAT token");
                }
                EatError::InvalidData => {
                    println!("  Error: Invalid data provided");
                }
                EatError::MissingMandatoryClaim => {
                    println!("  Error: Missing mandatory claim");
                }
                EatError::InvalidClaimSize => {
                    println!("  Error: Invalid claim size");
                }
                EatError::EncodingError => {
                    println!("  Error: CBOR encoding error");
                }
                EatError::InvalidUtf8 => {
                    println!("  Error: Invalid UTF-8 string");
                }
            }
            return Err(format!("EAT encoding failed: {:?}", error).into());
        }
    }

    Ok(())
}

// Fallback main function when crypto features are disabled
#[cfg(not(feature = "crypto"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Check for decode mode (works without crypto features)
    if args.len() > 1 && args[1] == "--decode" {
        if args.len() < 3 {
            println!("Usage: {} --decode <cbor_file>", args[0]);
            println!("       Decode an existing CBOR token using the Python decoder");
            println!();
            println!("Example:");
            println!("  {} --decode output/my_token.cbor", args[0]);
            return Ok(());
        }

        // Call the Python decoder (works without crypto features)
        return decode_cbor_file(&args[2]);
    }

    println!("=== OCP EAT Encoder Library (no_std/no_crypto mode) ===");
    println!("This library provides no_std compatible CBOR encoding for OCP EAT tokens.");
    println!("To run the cryptographic examples, build with:");
    println!("  cargo run --features std,crypto -- <output_file.cbor>");
    println!("To decode existing tokens:");
    println!("  cargo run -- --decode <cbor_file>");
    println!();
    println!("Examples:");
    println!(
        "  cargo run --features std,crypto -- my_eat_token.cbor  # Creates output/my_eat_token.cbor"
    );
    println!("  cargo run -- --decode output/my_eat_token.cbor        # Decode existing token");
    println!("\nFor library usage, see lib.rs documentation and examples.");

    if args.len() > 1 {
        println!("\nNote: Crypto features are required to generate EAT tokens.");
        println!(
            "The output file parameter '{}' will be ignored in this mode.",
            args[1]
        );
        println!(
            "Files would be saved to output/{} when crypto features are enabled.",
            args[1]
        );
    }

    Ok(())
}

fn print_hex_dump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}: ", i * 16);

        // Print hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x}", byte);
            if j % 2 == 1 {
                print!(" ");
            }
        }

        // Pad if necessary
        for _ in chunk.len()..16 {
            print!("  ");
            if chunk.len() % 2 == 0 {
                print!(" ");
            }
        }

        // Print ASCII representation
        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

#[cfg(feature = "std")]
fn save_token_to_file(data: &[u8], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create output directory if it doesn't exist
    let output_dir = Path::new("output");
    create_dir_all(output_dir)?;

    // Create full path by joining output directory with filename
    let full_path = output_dir.join(filename);

    let mut file = File::create(&full_path)?;
    file.write_all(data)?;
    println!("✓ Token saved to: {}", full_path.display());

    Ok(())
}

fn print_cbor_diagnostic(data: &[u8]) {
    println!("\nCBOR Structure Analysis (first {} bytes):", data.len());

    if data.is_empty() {
        println!("  (empty data)");
        return;
    }

    // Simple CBOR structure analysis
    let mut pos = 0;
    let mut depth = 0;

    while pos < data.len() && pos < 32 {
        // Limit analysis to first 32 bytes
        let byte = data[pos];
        let major_type = byte >> 5;
        let additional_info = byte & 0x1f;

        let indent = "  ".repeat(depth);

        match major_type {
            0 => {
                if additional_info <= 23 {
                    println!("{}Positive Integer: {}", indent, additional_info);
                    pos += 1;
                } else {
                    println!("{}Positive Integer (extended)", indent);
                    pos += 1 + (1 << (additional_info - 24));
                }
            }
            1 => {
                if additional_info <= 23 {
                    println!("{}Negative Integer: -{}", indent, additional_info + 1);
                    pos += 1;
                } else {
                    println!("{}Negative Integer (extended)", indent);
                    pos += 1 + (1 << (additional_info - 24));
                }
            }
            2 => {
                println!("{}Byte String", indent);
                pos += 1;
                if additional_info <= 23 {
                    pos += additional_info as usize;
                }
            }
            3 => {
                println!("{}Text String", indent);
                pos += 1;
                if additional_info <= 23 {
                    pos += additional_info as usize;
                }
            }
            4 => {
                println!(
                    "{}Array (length: {})",
                    indent,
                    if additional_info <= 23 {
                        additional_info as usize
                    } else {
                        0
                    }
                );
                depth += 1;
                pos += 1;
            }
            5 => {
                println!(
                    "{}Map (pairs: {})",
                    indent,
                    if additional_info <= 23 {
                        additional_info as usize
                    } else {
                        0
                    }
                );
                depth += 1;
                pos += 1;
            }
            6 => {
                println!("{}Tag ({})", indent, additional_info);
                pos += 1;
            }
            7 => match additional_info {
                20 => {
                    println!("{}False", indent);
                    pos += 1;
                }
                21 => {
                    println!("{}True", indent);
                    pos += 1;
                }
                22 => {
                    println!("{}Null", indent);
                    pos += 1;
                }
                23 => {
                    println!("{}Undefined", indent);
                    pos += 1;
                }
                31 => {
                    println!("{}Break", indent);
                    depth = depth.saturating_sub(1);
                    pos += 1;
                }
                _ => {
                    println!("{}Simple/Float value", indent);
                    pos += 1;
                }
            },
            _ => {
                println!("{}Unknown major type: {}", indent, major_type);
                pos += 1;
            }
        }

        if pos >= data.len() {
            break;
        }
    }

    if pos < data.len() {
        println!("  ... ({} more bytes)", data.len() - pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_eat_creation() {
        let mut buffer = vec![0u8; 4096];
        let evidence = create_mock_concise_evidence_structured();
        let device_key = DeviceKey::generate().unwrap();

        let result = create_example_eat(&mut buffer, "CN=Test Device", &evidence, &device_key);

        assert!(result.is_ok());
        let size = result.unwrap();
        assert!(size > 0);
        assert!(size < buffer.len());
    }

    #[test]
    fn test_buffer_size_estimation() {
        let cti = [0u8; 16];
        let nonce = [0u8; 16];
        let evidence = create_mock_concise_evidence_structured();
        let measurement = MeasurementFormat::new(&evidence);
        let measurements = [measurement];

        let mut claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);
        claims.issuer = Some("Test Issuer");
        claims.cti = Some(&cti);

        let estimated = claims.estimate_buffer_size();
        assert!(estimated > 100); // Should be reasonable size
        assert!(estimated < 65536); // Should be within limits
    }

    #[test]
    fn test_claims_validation() {
        let cti = [0u8; 16]; // Valid size
        let nonce = [0u8; 16]; // Valid size
        let evidence = create_mock_concise_evidence_structured();
        let measurement = MeasurementFormat::new(&evidence);
        let measurements = [measurement];

        let mut claims = OcpEatClaims::new(&nonce, DebugStatus::Disabled, &measurements);
        claims.issuer = Some("Valid Issuer");
        claims.cti = Some(&cti);

        assert!(claims.validate().is_ok());

        // Test invalid CTI size
        let short_cti = [0u8; 4]; // Too short
        let invalid_measurement = MeasurementFormat::new(&evidence);
        let invalid_measurements = [invalid_measurement];
        let mut invalid_claims =
            OcpEatClaims::new(&nonce, DebugStatus::Disabled, &invalid_measurements);
        invalid_claims.issuer = Some("Valid Issuer");
        invalid_claims.cti = Some(&short_cti);

        assert!(invalid_claims.validate().is_err());
    }
}
