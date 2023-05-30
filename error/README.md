
## Error Codes 
| Component | Module | Description | Error Code |
| --- | ----------- | ----- | ----- | 
| Driver | SHA256 | Internal Error  |0x00020001 |
| Driver | SHA256 | Max Data Limit Reached  |0x00020002 |
| Driver | SHA256 | Invalid Slice  |0x00020003 |
| Driver | SHA256 | Array Index Out of Bounds  |0x00020004 |
| Driver | SHA384 | Read Data Key Vault Read Error |0x00030001 |
| Driver | SHA384 | Read Data Key Vault Write Error |0x00030002 |
| Driver | SHA384 | Read Data Key Vault Unknown Error |0x00030003 |
| Driver | SHA384 | Invalid State Error |0x00030007 |
| Driver | SHA384 | Max Data Error |0x00030008 |
| Driver | HMAC384 | ReadKeyKvRead Error |0x00040001 |
| Driver | HMAC384 | ReadKeyKvWrite Error |0x00040002 |
| Driver | HMAC384 | ReadKeyKvUnknown Error |0x00040003 |
| Driver | HMAC384 | ReadData Kv Read Error |0x00040004 |
| Driver | HMAC384 | ReadData Kv Write Error |0x00040005 |
| Driver | HMAC384 | ReadData Kv Unknown Error |0x00040006 |
| Driver | HMAC384 | Write Tag Kv Read Error |0x00040007 |
| Driver | HMAC384 | Write Tag Kv Write Error |0x00040008 |
| Driver | HMAC384 | Write Tag Kv Unknown Error |0x00040009 |
| Driver | HMAC384 | Invalid Key Size Error |0x0004000A |
| Driver | HMAC384 | Invalid State Error |0x0004000B |
| Driver | HMAC384 | Max Data Error |0x0004000C |
| Driver | HMAC384 | Invalid Slice Error |0x0004000D |
| Driver | HMAC384 | Index Out of Bounds Error |0x0004000E |
| Driver | ECC384 | ReadSeedKvRead |0x00050001 |
| Driver | ECC384 | ReadSeedKvWrite |0x00050002 |
| Driver | ECC384 | ReadSeedKvUnknown |0x00050003 |
| Driver | ECC384 | WritePrivKeyKvRead |0x00050004 |
| Driver | ECC384 | WritePrivKeyKvWrite |0x00050005 |
| Driver | ECC384 | WritePrivKeyKvUnknown |0x00050006 |
| Driver | ECC384 | ReadPrivKeyKvRead |0x00050007 |
| Driver | ECC384 | ReadPrivKeyKvWrite |0x00050008 |
| Driver | ECC384 | ReadPrivKeyKvUnknown |0x00050009 |
| Driver | ECC384 | ReadDataKvRead |0x0005000A |
| Driver | ECC384 | ReadDataKvWrite |0x0005000B |
| Driver | ECC384 | ReadDataKvUnknown |0x0005000C |
| Driver | Key Vault | Erase failed due to use lock was set|0x00060001 |
| Driver | Key Vault | Erase failed due to write lock was set|0x00060002 |
| Driver | Pcr Bank | Erase failed due to write lock st |0x00070001 |
| Driver | Mailbox | Invalid State Error |0x00080001 |
| Driver | Mailbox | Invalid Data Length Error |0x00080002 |
| Driver | Mailbox | No Data Available Error |0x00080003 |
| Driver | Mailbox | Enqueue Error |0x00080004 |
| Driver | Mailbox | Dequeue Error |0x00080005 |
| Driver | SHA384Acc | Invalid Op |0x00090001 |
| Driver | SHA384Acc | Max Data Err |0x00090002 |
| Driver | SHA384Acc | Index Out of Bounds |0x00090003 |
| Driver | SHA1 | Invalid State Error |0x000A0001 |
| Driver | SHA1 | Max Data Error |0x000A0002 |
| Driver | SHA1 | Invalid Slice Error |0x000A0003 |
| Driver | SHA1 | Index Out of Bounds Error |0x000A0004 |
| Image Verifier | Verifier | ManifestMarkerMismatch |0x000B0001 |
| Image Verifier | Verifier | ManifestSizeMismatch |0x000B0002 |
| Image Verifier | Verifier | VendorPubKeyDigestInvalid |0x000B0003 |
| Image Verifier | Verifier | VendorPubKeyDigestFailure |0x000B0004 |
| Image Verifier | Verifier | VendorPubKeyDigestMismatch |0x000B0005 |
| Image Verifier | Verifier | OwnerPubKeyDigestFailure |0x000B0006 |
| Image Verifier | Verifier | OwnerPubKeyDigestMismatch |0x000B0007 |
| Image Verifier | Verifier | VendorEccPubKeyIndexOutOfBounds |0x000B0008 |
| Image Verifier | Verifier | VendorEccPubKeyRevoked |0x000B0009 |
| Image Verifier | Verifier | HeaderDigestFailure |0x000B000A |
| Image Verifier | Verifier | VendorEccVerifyFailure |0x000B000B |
| Image Verifier | Verifier | VendorEccSignatureInvalid |0x000B000C |
| Image Verifier | Verifier | VendorEccPubKeyIndexMismatch |0x000B000D |
| Image Verifier | Verifier | OwnerEccVerifyFailure |0x000B000E |
| Image Verifier | Verifier | OwnerEccSignatureInvalid |0x000B000F |
| Image Verifier | Verifier | TocEntryCountInvalid |0x000B0010 |
| Image Verifier | Verifier | TocDigestFailures |0x000B0011 |
| Image Verifier | Verifier | TocDigestMismatch |0x000B0012 |
| Image Verifier | Verifier | FmcDigestFailure |0x000B0013 |
| Image Verifier | Verifier | FmcDigestMismatch |0x000B0014 |
| Image Verifier | Verifier | RuntimeDigestFailure |0x000B0015 |
| Image Verifier | Verifier | RuntimeDigestMismatch |0x000B0016 |
| Image Verifier | Verifier | FmcRuntimeOverlap |0x000B0017 |
| Image Verifier | Verifier | FmcRuntimeIncorrectOrder |0x000B0018 |
| Image Verifier | Verifier | OwnerPubKeyDigestInvalidArg |0x000B0019 |
| Image Verifier | Verifier | OwnerEccSignatureInvalidArg |0x000B001A |
| Image Verifier | Verifier | VendorPubKeyDigestInvalidArg |0x000B001B |
| Image Verifier | Verifier | VendorEccSignatureInvalidArg |0x000B001C |
| Image Verifier | Verifier | UpdateResetOwnerDigestFailure |0x000B001D |
| Image Verifier | Verifier | UpdateResetVenPubKeyIdxMismatch |0x000B001E |
| Image Verifier | Verifier | UpdateResetFmcDigestMismatch |0x000B001F |
| Image Verifier | Verifier | UpdateResetVenPubKeyIdxOutOfBounds |0x000B0020 |
| Image Verifier | Verifier | FmcLoadAddrInvalid |0x000B0021 |
| Image Verifier | Verifier | FmcLoadAddrUnaligned |0x000B0022 |
| Image Verifier | Verifier | FmcEntryPointInvalid |0x000B0023 |
| Image Verifier | Verifier | FmcEntryPointUnaligned |0x000B0024 |
| Image Verifier | Verifier | FmcSvnGreaterThanMaxSupported |0x000B0025 |
| Image Verifier | Verifier | FmcSvnLessThanMinSupported |0x000B0026 |
| Image Verifier | Verifier | FmcSvnLessThanFuse |0x000B0027 |
| Image Verifier | Verifier | RuntimeLoadAddrInvalid |0x000B0028 |
| Image Verifier | Verifier | RuntimeLoadAddrUnaligned |0x000B0029 |
| Image Verifier | Verifier | RuntimeEntryPointInvalid |0x000B002A |
| Image Verifier | Verifier | RuntimeEntryPointUnaligned |0x000B002B |
| Image Verifier | Verifier | RuntimeSvnGreaterThanMaxSupported |0x000B002C |
| Image Verifier | Verifier | RuntimeSvnLessThanMinSupported |0x000B002D |
| Image Verifier | Verifier | RuntimeSvnLessThanFuse |0x000B002E |
| Driver | LMS | InvalidLmsAlgorithmType |0x000C0001 |
| Driver | LMS | InvalidLmotsAlgorithmType |0x000C0002 |
| Driver | LMS | InvalidWinternitzParameter |0x000C0003 |
| Driver | LMS | InvalidPValue |0x000C0004 |
| Driver | LMS | InvalidHashWidth |0x000C0005 |
| Driver | LMS | InvalidTreeHeight |0x000C0006 |
| Driver | LMS | InvalidQValue |0x000C0007 |
| Driver | LMS | InvalidIndex |0x000C0008 |
| Driver | LMS | PathOutOfBounds |0x000C0009 |
| Driver | CSRNG | Instantiate Error |0x000d0001 |
| Driver | CSRNG | Uninstantiate Error |0x000d0002 |
| Driver | CSRNG | Reseed Error |0x000d0003 |
| Driver | CSRNG | Generate Error |0x000d0004 |
| Driver | CSRNG | Update Error |0x000d0005 |
| Runtime | Command Handler | Internal Error  |0x000e0001 |
| Runtime | Command Handler | Unimplemented Command  |0x000e0002 |
| Runtime | Command Handler | Insufficient Memory  |0x000e0003 |
| ROM | IDEVID | CSR Builder Init Failure  |0x01000001 |
| ROM | IDEVID | CSR Builder Build Failure  |0x01000002 |
| ROM | IDEVID | Invalid CSR  |0x01000003 |
| ROM | IDEVID | CSR Verification Failure  |0x01000004 |
| ROM | IDEVID | CSR Overflow  |0x01000005 |
| ROM | LDEVID | Certificate Verification Failure  |0x01010001 |
| ROM | FMC Alias Layer | Certificate Verification Failure  |0x01020001 |
| ROM | FMC Alias Layer | Caliptra Image Bundle Manifest Read Failure  |0x01020002 |
| ROM | FMC Alias Layer | Caliptra Image Bundle Invalid Image Size  |0x01020003 |
| ROM | FMC Alias Layer | Mailbox state inconsistent  |0x01020004 |
| ROM | Update Reset Flow | Caliptra Image Bundle Manifest Read Failure  |0x01030002 |
| ROM | Update Reset Flow | Invalid Firmware Command  |0x01030003 |
| ROM | Update Reset Flow | Mailbox Access Failure  |0x01030004 |
| ROM | Global Scope | Non Maskable Interrupt  |0x01040001 |
| ROM | Global Scope | Exception  |0x01040002 |
| ROM | Global Scope | Panic  |0x01040003 |
| KAT | SHA256 | Digest Failure  |0x90010001 |
| KAT | SHA256 | Digest Mismatch  |0x90010002 |
| KAT | SHA384 | Digest Failure  |0x90020001 |
| KAT | SHA384 | Digest Mismatch  |0x90020002 |
| KAT | HMAC384 | HMAC Failure  |0x90030001 |
| KAT | HMAC384 | HMAC Tag Mismatch  |0x90030002 |
| KAT | ECC384 | Signature Generation Failure  |0x90040001 |
| KAT | ECC384 | Signature Verification Failure  |0x90040002 |
| KAT | ECC384 | Signature Mismatch  |0x90040003 |
| KAT | SHA384 Accel | Digest Start Operation Failure  |0x90050001 |
| KAT | SHA384 Accel | Digest Failure  |0x90050002 |
| KAT | SHA384 Accel | Digest Mismatch  |0x90050003 |
| KAT | SHA1 | Digest Failure  |0x90060001 |
| KAT | SHA1 | Digest Mismatch  |0x90060002 |
| KAT | LMS | Digest Failure  |0x90070001 |
| KAT | LMS | Digest Mismatch  |0x90070002 |

