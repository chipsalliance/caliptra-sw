# OCP EAT Token Generator & Decoder

## Features

This binary provides both generation and decoding of OCP EAT (Entity Attestation Token) CBOR files.

### Generation Mode
- Automatically creates an `output/` folder and saves all generated CBOR tokens there
- Supports structured concise evidence with IETF CoRIM format
- Generates cryptographically signed tokens with X.509 certificates

### Decode Mode  
- Decodes existing CBOR tokens using the integrated Python decoder
- Performs signature validation and certificate analysis
- Displays detailed EAT claims analysis and CBOR structure breakdown

## Usage

### Generate Tokens
```bash
# Generate a token - automatically saved to output/my_token.cbor
cargo run --features std,crypto -- my_token.cbor

# View generated tokens
ls -la output/
```

## Directory Structure
```
runtime/userspace/api/eat/
├── src/                    # Rust source code
│   ├── main.rs            # Main binary with CLI (generation & decode modes)
│   ├── lib.rs             # Library implementation
│   ├── cbor.rs            # CBOR encoding utilities
│   ├── cose.rs            # COSE signature utilities
│   ├── claim_key.rs       # EAT claim key definitions
│   └── error.rs           # Error handling modules
│   └── ocp_profile/       # OCP profile-specific EAT claims encoding modules for attestation
│   └── csr_eat.rs         # Envelope Signed CSR EAT claims encoding module
├── output/                # Auto-created output directory for tokens
│   └── *.cbor            # Generated CBOR token files
├── Cargo.toml            # Rust package manifest
└── OUTPUT_README.md      # This documentation
```

## Requirements

### For Token Generation
- **Rust Features**: Requires `std` and `crypto` features
- **Output folder**: Automatically created if it doesn't exist
