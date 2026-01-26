#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
COSE Sign1 signature validation
"""

def validate_cose_signature(protected_headers, payload, signature, certificate):
    """
    Validate COSE Sign1 signature using extracted certificate
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Try to import cryptography library for signature validation
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import hashlib
        
        print(f"\n--- COSE Sign1 Signature Validation ---")
        
        # Try to parse the X.509 certificate
        try:
            cert = x509.load_der_x509_certificate(certificate)
            public_key = cert.public_key()
        except Exception as cert_error:
            print(f"Certificate parsing failed: {cert_error}")
            print(f"This appears to be a test/mock certificate")
            
            # Try to extract public key directly from certificate structure
            # Look for the P-384 public key pattern in the certificate
            cert_hex = certificate.hex()
            
            # Look for secp384r1 curve OID: 2b8104002200 (1.3.132.0.34)
            if '2b8104002200' in cert_hex:
                print(f"Found P-384 curve identifier in certificate")
                
                # Look for uncompressed point marker (04) followed by coordinates
                pubkey_start = cert_hex.find('04') 
                if pubkey_start >= 0:
                    # P-384 uncompressed public key: 04 + 48 bytes x + 48 bytes y = 97 bytes total
                    pubkey_hex = cert_hex[pubkey_start:pubkey_start + 194]  # 97 * 2
                    if len(pubkey_hex) == 194:
                        print(f"Extracted P-384 public key: {pubkey_hex[:32]}...")
                        print(f"Note: Cannot validate signature with mock certificate")
                        return False
            
            print(f"Could not extract valid public key from mock certificate")
            return False
        
        print(f"Certificate Subject: {cert.subject}")
        print(f"Certificate Issuer: {cert.issuer}")
        print(f"Public Key Type: {type(public_key).__name__}")
        
        # Verify it's an ECDSA key
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            print(f"ERROR: Expected ECDSA key, got {type(public_key).__name__}")
            return False
            
        curve_name = public_key.curve.name
        print(f"Curve: {curve_name}")
        
        # Create COSE Sign1 signature context (Sig_structure)
        # Sig_structure = [
        #   "Signature1",    // Context identifier
        #   protected,       // Protected headers (as byte string)
        #   "",              // External AAD (empty for Sign1)
        #   payload          // Payload
        # ]
        
        import cbor2
        
        sig_structure = [
            "Signature1",
            protected_headers,
            b"",  # empty external AAD
            payload
        ]
        
        # Encode the signature structure as CBOR
        sig_context = cbor2.dumps(sig_structure)
        print(f"Signature context length: {len(sig_context)} bytes")
        print(f"Signature context (first 32 bytes): {sig_context[:32].hex()}")
        
        # Hash the signature context (SHA-384 for P-384)
        if curve_name == "secp384r1":
            hash_algorithm = hashes.SHA384()
            hasher = hashlib.sha384()
        else:
            print(f"WARNING: Unknown curve {curve_name}, assuming SHA-256")
            hash_algorithm = hashes.SHA256()
            hasher = hashlib.sha256()
            
        hasher.update(sig_context)
        message_hash = hasher.digest()
        print(f"Message hash ({len(message_hash)} bytes): {message_hash.hex()}")
        
        # Verify the signature
        try:
            public_key.verify(signature, sig_context, ec.ECDSA(hash_algorithm))
            print(f"✓ SIGNATURE VALID: ECDSA signature verification successful")
            return True
        except Exception as verify_error:
            print(f"✗ SIGNATURE INVALID: {verify_error}")
            return False
            
    except ImportError:
        print(f"Note: cryptography library not available for signature validation")
        print(f"Install with: pip install cryptography cbor2")
        return False
    except Exception as e:
        print(f"Error during signature validation: {e}")
        return False