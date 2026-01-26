#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""
Enhanced COSE signature analysis for decode.py
"""

def analyze_cose_signature(signature):
    """Analyze COSE Sign1 signature structure"""
    print(f"\n--- Enhanced Signature Analysis ---")
    print(f"Signature ({len(signature)} bytes): {signature.hex()}")
    
    # Try to parse as DER-encoded ECDSA signature
    try:
        if len(signature) > 6 and signature[0] == 0x30:  # DER SEQUENCE
            sig_len = signature[1]
            print(f"DER-encoded ECDSA signature (declared length: {sig_len})")
            
            # Parse r component
            if signature[2] == 0x02:  # INTEGER
                r_len = signature[3]
                r_value = signature[4:4+r_len]
                print(f"  r component ({r_len} bytes): {r_value.hex()}")
                
                # Parse s component
                s_offset = 4 + r_len
                if s_offset < len(signature) and signature[s_offset] == 0x02:  # INTEGER
                    s_len = signature[s_offset + 1]
                    s_value = signature[s_offset + 2:s_offset + 2 + s_len]
                    print(f"  s component ({s_len} bytes): {s_value.hex()}")
                                           
    except Exception as e:
        print(f"Error analyzing signature structure: {e}")

def analyze_certificate_headers(key_value, value_data):
    """Analyze certificate in unprotected headers"""
    if key_value == 33:  # X5CHAIN
        print(f"  Key {key_value} (X5CHAIN): Certificate chain ({len(value_data)} bytes)")
        print(f"    Certificate DER (first 32 bytes): {value_data[:32].hex()}")
        
        # Try to identify certificate type
        if value_data[:2] == b'\x30\x82':
            import struct
            cert_len = struct.unpack('>H', value_data[2:4])[0]
            print(f"    X.509 certificate (declared length: {cert_len + 4} bytes)")
            
            # Look for common certificate fields
            cert_str = value_data.hex()
            if '2a8648ce3d020106' in cert_str:  # ecPublicKey OID
                print(f"    Algorithm: ECDSA (Elliptic Curve Public Key)")
            if '2b8104002200' in cert_str:  # secp384r1 OID
                print(f"    Curve: secp384r1 (P-384)")
            if '2a8648ce3d040303' in cert_str:  # ecdsaWithSHA384 OID
                print(f"    Signature Algorithm: ECDSA with SHA-384")
                
        return True
    return False