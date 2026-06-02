# ROM Test Coverage

This document tracks the currently compiled ROM integration tests under
`rom/dev/tests/rom_integration_tests`. The test entry point imports these
modules from `main.rs`, and the inventory below includes all current `#[test]`
functions grouped by logical coverage area.

Total current tests: **184**

Run the harness with:

```bash
cargo test -p caliptra-rom --test rom_integration_tests
```

The `Expected Result / ROM Error Code` column lists the asserted error when the
test checks a specific `CaliptraError`. `N/A` means the test expects successful
behavior or checks state/data without expecting a ROM error code.

## Coverage Summary

| Logical Area | Count | Primary Modules |
| --- | ---: | --- |
| Secure boot and image validation | 75 | `test_image_validation.rs` |
| Firmware download, FMC alias, logs, and measurements | 13 | `test_fmcalias_derivation.rs` |
| Identity, DICE, and certificate commands | 12 | `test_dice_derivations.rs`, `test_idevid_derivation.rs`, `tests_get_idev_csr.rs`, `test_ldev_cert_cmd.rs` |
| Reset, watchdog, and fatal trap handling | 20 | `test_update_reset.rs`, `test_warm_reset.rs`, `test_wdt_activation_and_stoppage.rs`, `test_cpu_fault.rs` |
| Mailbox commands and ROM services | 22 | `test_mailbox_errors.rs`, `test_cm_sha.rs`, `test_derive_stable_key.rs`, `test_capabilities.rs`, `test_version.rs`, `test_ecdsa_verify.rs`, `test_mldsa_verify.rs` |
| Debug unlock, UDS/FE, and hardware protections | 28 | `test_debug_unlock.rs`, `test_uds_fe.rs`, `test_ocp_lock.rs`, `test_pmp.rs`, `test_cfi.rs`, `test_fips_hooks.rs` |
| ROM configuration, integrity, and test infrastructure | 14 | `test_fake_rom.rs`, `test_rom_integrity.rs`, `test_panic_missing.rs`, `test_symbols.rs`, `rv32_unit_tests.rs`, `helpers.rs` |

## Secure Boot and Image Validation

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Reject a manifest with an invalid marker | `test_invalid_manifest_marker` | `IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH` |
| Reject a manifest with an invalid size | `test_invalid_manifest_size` | `IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH` |
| Reject an invalid PQC key type value in the image/fuse configuration | `test_invalid_pqc_key_type` | `IMAGE_VERIFIER_ERR_PQC_KEY_TYPE_INVALID` |
| Reject an image whose PQC key type does not match the provisioned fuse setting | `test_pqc_key_type_mismatch` | `IMAGE_VERIFIER_ERR_PQC_KEY_TYPE_MISMATCH` |
| Validate PQC key type behavior when device fuses are not provisioned | `test_pqc_key_type_unprovisioned` | N/A |
| Reject a zero vendor public key digest in fuses | `test_preamble_zero_vendor_pubkey_info_digest` | `IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID` |
| Reject a preamble whose vendor public key info digest does not match fuses | `test_preamble_vendor_pubkey_info_digest_mismatch` | `IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH` |
| Reject a mismatch in the active vendor ECC public key digest | `test_preamble_vendor_active_ecc_pubkey_digest_mismatch` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_DIGEST_MISMATCH` |
| Reject a mismatch in the active vendor MLDSA public key digest | `test_preamble_vendor_active_mldsa_pubkey_digest_mismatch` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_DIGEST_MISMATCH` |
| Reject a mismatch in the vendor LMS public key descriptor digest | `test_preamble_vendor_lms_pubkey_descriptor_digest_mismatch` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_DIGEST_MISMATCH` |
| Reject an out-of-range ECC public key descriptor index in the preamble | `test_preamble_vendor_ecc_pubkey_descriptor_bad_index` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS` |
| Reject an out-of-range LMS public key descriptor index in the preamble | `test_preamble_vendor_lms_pubkey_descriptor_bad_index` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_OUT_OF_BOUNDS` |
| Reject an out-of-range MLDSA public key descriptor index in the preamble | `test_preamble_vendor_mldsa_pubkey_descriptor_bad_index` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_OUT_OF_BOUNDS` |
| Reject an owner public key digest mismatch | `test_preamble_owner_pubkey_digest_mismatch` | `IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH` |
| Reject a DOT owner public key digest mismatch | `test_preamble_dot_owner_pubkey_digest_mismatch` | `IMAGE_VERIFIER_ERR_DOT_OWNER_PUB_KEY_DIGEST_MISMATCH` |
| Accept a valid DOT owner public key digest | `test_preamble_dot_owner_pubkey_digest_success` | N/A |
| Reject revoked vendor ECC public key indexes and allow the non-revocable last index | `test_preamble_vendor_ecc_pubkey_revocation` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED` |
| Reject revoked vendor LMS public key indexes and allow the non-revocable last index | `test_preamble_vendor_lms_pubkey_revocation` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_REVOKED` |
| Reject revoked vendor MLDSA public key indexes and allow the non-revocable last index | `test_preamble_vendor_mldsa_pubkey_revocation` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_REVOKED` |
| Reject a vendor ECC public key index outside the supported range | `test_preamble_vendor_ecc_pubkey_out_of_bounds` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS` |
| Reject a vendor LMS public key index outside the supported range | `test_preamble_vendor_lms_pubkey_out_of_bounds` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_OUT_OF_BOUNDS` |
| Reject a vendor ECC signature check with a zero public key | `test_header_verify_vendor_sig_zero_ecc_pubkey` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INVALID_ARG` |
| Reject a vendor ECC signature check with a zero signature | `test_header_verify_vendor_sig_zero_ecc_signature` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG` |
| Reject a mismatched vendor ECC signature over the header | `test_header_verify_vendor_ecc_sig_mismatch` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID` |
| Reject a mismatched vendor LMS signature over the header | `test_header_verify_vendor_lms_sig_mismatch` | `IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID` |
| Reject a mismatched owner LMS signature over the header | `test_header_verify_owner_lms_sig_mismatch` | `IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID` |
| Reject a vendor ECC public key index mismatch between preamble and header | `test_header_verify_vendor_ecc_pub_key_in_preamble_and_header` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH` |
| Reject a vendor LMS public key index mismatch between preamble and header | `test_header_verify_vendor_lms_pub_key_in_preamble_and_header` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_MISMATCH` |
| Validate owner signature behavior when owner fuses are zero | `test_header_verify_owner_sig_zero_fuses` | N/A |
| Reject an owner ECC signature check with public key X set to zero | `test_header_verify_owner_ecc_sig_zero_pubkey_x` | `IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG` |
| Reject an owner ECC signature check with public key Y set to zero | `test_header_verify_owner_ecc_sig_zero_pubkey_y` | `IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG` |
| Reject an owner ECC signature with R set to zero | `test_header_verify_owner_ecc_sig_zero_signature_r` | `IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG` |
| Reject an owner ECC signature with S set to zero | `test_header_verify_owner_ecc_sig_zero_signature_s` | `IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG` |
| Reject an invalid owner ECC signature R value | `test_header_verify_owner_ecc_sig_invalid_signature_r` | `IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID` |
| Reject an invalid owner ECC signature S value | `test_header_verify_owner_ecc_sig_invalid_signature_s` | `IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID` |
| Reject an invalid TOC entry count | `test_toc_invalid_entry_count` | `IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID` |
| Reject a TOC digest mismatch | `test_toc_invalid_toc_digest` | `IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH` |
| Reject a zero-sized FMC image | `test_toc_fmc_size_zero` | `IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO` |
| Reject overlapping FMC and Runtime ranges in the bundle | `test_toc_fmc_range_overlap` | `IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP` |
| Reject FMC and Runtime ranges in the wrong order | `test_toc_fmc_range_incorrect_order` | `IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER` |
| Reject overlapping FMC and Runtime load address ranges | `test_fmc_rt_load_address_range_overlap` | `IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP` |
| Reject an FMC image digest mismatch | `test_fmc_digest_mismatch` | `IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH` |
| Reject an FMC load address before ICCM | `test_fmc_invalid_load_addr_before_iccm` | `IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID` |
| Reject an FMC load address after ICCM | `test_fmc_invalid_load_addr_after_iccm` | `IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID` |
| Reject an FMC image that is not fully contained in ICCM | `test_fmc_not_contained_in_iccm` | `IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID` |
| Reject an unaligned FMC load address | `test_fmc_load_addr_unaligned` | `IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED` |
| Reject an FMC entry point before ICCM | `test_fmc_invalid_entry_point_before_iccm` | `IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID` |
| Reject an FMC entry point after ICCM | `test_fmc_invalid_entry_point_after_iccm` | `IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID` |
| Reject an unaligned FMC entry point | `test_fmc_entry_point_unaligned` | `IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED` |
| Reject a zero-sized Runtime image | `test_toc_rt_size_zero` | `IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO` |
| Reject a Runtime image digest mismatch | `test_runtime_digest_mismatch` | `IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH` |
| Reject a Runtime load address before ICCM | `test_runtime_invalid_load_addr_before_iccm` | `IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID` |
| Reject a Runtime load address after ICCM | `test_runtime_invalid_load_addr_after_iccm` | `IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID` |
| Reject a Runtime image that is not fully contained in ICCM | `test_runtime_not_contained_in_iccm` | `IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID` |
| Reject an unaligned Runtime load address | `test_runtime_load_addr_unaligned` | `IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED` |
| Reject a Runtime entry point before ICCM | `test_runtime_invalid_entry_point_before_iccm` | `IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID` |
| Reject a Runtime entry point after ICCM | `test_runtime_invalid_entry_point_after_iccm` | `IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID` |
| Reject an unaligned Runtime entry point | `test_runtime_entry_point_unaligned` | `IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED` |
| Reject a Runtime SVN greater than the maximum supported value | `test_runtime_svn_greater_than_max` | `IMAGE_VERIFIER_ERR_FIRMWARE_SVN_GREATER_THAN_MAX_SUPPORTED` |
| Reject a Runtime SVN lower than the fused SVN | `test_runtime_svn_less_than_fuse_svn` | `IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE` |
| Reject Runtime SVN corruption that invalidates the signed header | `test_runtime_svn_corruption` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID` |
| Generate LDEVID and FMC alias certificates with custom validity dates | `cert_test_with_custom_dates` | N/A |
| Generate LDEVID and FMC alias certificates | `cert_test` | N/A |
| Generate certificates with UEID extension coverage | `cert_test_with_ueid` | N/A |
| Load and verify a maximum-sized firmware image | `test_max_fw_image` | N/A |
| Verify a valid MLDSA-signed image bundle | `test_mldsa_verification` | N/A |
| Reject a zero vendor MLDSA signature | `test_header_verify_vendor_mldsa_sig_zero` | `IMAGE_VERIFIER_ERR_VENDOR_MLDSA_VERIFY_FAILURE` |
| Reject a vendor MLDSA signature when verified with the wrong public key | `test_header_verify_vendor_mldsa_sig_verify_fail_incorrect_pubkey` | `IMAGE_VERIFIER_ERR_VENDOR_MLDSA_SIGNATURE_INVALID` |
| Reject a corrupted vendor MLDSA signature | `test_header_verify_vendor_mldsa_verify_fail_incorrect_sig` | `IMAGE_VERIFIER_ERR_VENDOR_MLDSA_SIGNATURE_INVALID` |
| Reject an owner MLDSA signature when verified with the wrong public key | `test_header_verify_owner_mldsa_sig_verify_fail_incorrect_pubkey` | `IMAGE_VERIFIER_ERR_OWNER_MLDSA_SIGNATURE_INVALID` |
| Reject a corrupted owner MLDSA signature | `test_header_verify_owner_mldsa_sig_verify_fail_incorrect_sig` | `IMAGE_VERIFIER_ERR_OWNER_MLDSA_SIGNATURE_INVALID` |
| Reject a zero owner MLDSA signature | `test_header_verify_owner_mldsa_sig_verify_fail_zero_sig` | `IMAGE_VERIFIER_ERR_OWNER_MLDSA_VERIFY_FAILURE` |
| Reject a vendor MLDSA public key index mismatch between preamble and header | `test_header_verify_vendor_mldsa_pub_key_in_preamble_and_header` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_MISMATCH` |
| Reject a vendor MLDSA public key index outside the supported range | `test_preamble_vendor_mldsa_pubkey_out_of_bounds` | `IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_OUT_OF_BOUNDS` |
| Accept a firmware bundle padded to 256 KiB | `test_fw_padded_256k` | N/A |

## Firmware Download, FMC Alias, Logs, and Measurements

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Reject zero-sized firmware during firmware download | `test_zero_firmware_size` | `FW_PROC_INVALID_IMAGE_SIZE` |
| Reject firmware larger than the maximum supported size | `test_firmware_gt_max_size` | `FW_PROC_INVALID_IMAGE_SIZE` |
| Verify PCR log entries are written to DCCM | `test_pcr_log` | N/A |
| Verify PCR log entries when owner public key digest fuse is absent | `test_pcr_log_no_owner_key_digest_fuse` | N/A |
| Verify PCR log entries include FMC fuse SVN | `test_pcr_log_fmc_fuse_svn` | N/A |
| Verify PCR log entries survive update reset | `test_pcr_log_across_update_reset` | N/A |
| Verify fuse log entries are written to DCCM | `test_fuse_log` | N/A |
| Verify firmware handoff table entries are populated correctly | `test_fht_info` | N/A |
| Verify the ROM cold-boot status datavault register | `test_check_rom_cold_boot_status_reg` | N/A |
| Upload a single measurement through the ROM mailbox flow | `test_upload_single_measurement` | N/A |
| Upload the maximum supported number of measurements | `test_upload_measurement_limit` | N/A |
| Reject one measurement more than the supported limit | `test_upload_measurement_limit_plus_one` | `FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT` |
| Upload no measurements and verify the flow remains valid | `test_upload_no_measurement` | N/A |

## Identity, DICE, and Certificate Commands

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Verify cold-reset boot status reporting during DICE derivation | `test_cold_reset_status_reporting` | N/A |
| Verify successful cold-reset DICE derivation | `test_cold_reset_success` | N/A |
| Verify cold-reset behavior when RNG is unavailable | `test_cold_reset_no_rng` | N/A |
| Generate and download the IDEVID CSR envelope | `test_generate_csr_envelop` | N/A |
| Exercise IDEVID subject key identifier algorithms | `test_idev_subj_key_id_algo` | N/A |
| Stress CSR generation and certificate validation across many UDS identities | `test_generate_csr_envelop_stress` | N/A |
| Retrieve an ECC IDEVID CSR through the mailbox command | `test_get_ecc_csr` | N/A |
| Reject GET_IDEV_CSR when CSR generation was not enabled by fuse | `test_get_csr_generate_csr_flag_not_set` | `FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR` |
| Validate the MAC returned with the IDEVID CSR | `test_validate_csr_mac` | N/A |
| Retrieve an MLDSA IDEVID CSR through the mailbox command | `test_get_mldsa_csr` | N/A |
| Retrieve an ECC384 LDEVID certificate through the mailbox command | `test_ldev_ecc384_cert` | N/A |
| Retrieve an MLDSA87 LDEVID certificate through the mailbox command | `test_ldev_mldsa87_cert` | N/A |

## Reset, Watchdog, and Fatal Trap Handling

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Complete a successful update reset flow | `test_update_reset_success` | N/A |
| Reject update reset when no firmware mailbox command is available | `test_update_reset_no_mailbox_cmd` | `ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE` |
| Reject update reset when the pending mailbox command is not firmware load | `test_update_reset_non_fw_load_cmd` | `ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND` |
| Reject update reset with an invalid firmware image | `test_update_reset_verify_image_failure` | `IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH` |
| Verify update-reset boot status reporting | `test_update_reset_boot_status` | N/A |
| Reject update reset when the vendor ECC key index does not match datavault state | `test_update_reset_vendor_ecc_pub_key_idx_dv_mismatch` | `IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH` |
| Reject update reset when the vendor LMS/PQC key index does not match datavault state | `test_update_reset_vendor_lms_pub_key_idx_dv_mismatch` | `IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_PQC_PUB_KEY_IDX_MISMATCH` |
| Verify the ROM update-reset status datavault register | `test_check_rom_update_reset_status_reg` | N/A |
| Verify the FMC image size expectation used by update reset | `test_fmc_is_16k` | N/A |
| Update reset with a maximum-sized firmware image | `test_update_reset_max_fw_image` | N/A |
| Complete a successful warm reset flow | `test_warm_reset_success` | N/A |
| Reject warm reset during cold boot before image validation | `test_warm_reset_during_cold_boot_before_image_validation` | `ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET` |
| Reject warm reset during cold boot while image validation is in progress | `test_warm_reset_during_cold_boot_during_image_validation` | `ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET` |
| Reject warm reset during cold boot after image validation | `test_warm_reset_during_cold_boot_after_image_validation` | `ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET` |
| Reject warm reset during update reset | `test_warm_reset_during_update_reset` | `ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET` |
| Verify VERSION behavior across warm reset | `test_warm_reset_version` | N/A |
| Verify watchdog timers are activated and stopped in the expected boot phases | `test_wdt_activation_and_stoppage` | N/A |
| Verify watchdog timers are not enabled on debug parts | `test_wdt_not_enabled_on_debug_part` | N/A |
| Verify ROM fatal error reporting on watchdog timeout | `test_rom_wdt_timeout` | `ROM_GLOBAL_WDT_EXPIRED` |
| Trigger a CPU fault and verify extended error information is populated | `test_cpu_fault` | `ROM_GLOBAL_EXCEPTION` |

## Mailbox Commands and ROM Services

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Return ROM capability information | `test_capabilities` | N/A |
| Return ROM version information | `test_version` | N/A |
| Execute CM_SHA with SHA-384 | `test_cm_sha_sha384` | N/A |
| Execute CM_SHA with SHA-512 | `test_cm_sha_sha512` | N/A |
| Execute CM_SHA with empty input | `test_cm_sha_empty_input` | N/A |
| Reject CM_SHA with an invalid algorithm | `test_cm_sha_invalid_algorithm` | `FW_PROC_MAILBOX_INVALID_PARAMS` |
| Execute CM_SHA with a full active mailbox buffer | `test_cm_sha_full_mailbox_all_0xff` | N/A |
| Execute CM_SHA with a full passive mailbox buffer | `test_cm_sha_full_passive_mailbox_all_0xff` | N/A |
| Verify the ECDSA verify mailbox command failure path | `test_ecdsa_verify_cmd` | `ROM_ECDSA_VERIFY_FAILED` |
| Verify the MLDSA verify mailbox command failure path | `test_mldsa_verify_cmd` | `ROM_MLDSA_VERIFY_FAILED` |
| Derive stable keys and verify encrypted CMK behavior | `test_derive_stable_key` | N/A |
| Reject stable-key derivation with an invalid key type | `test_derive_stable_key_invalid_key_type` | `DOT_INVALID_KEY_TYPE` |
| Verify different info values produce different stable owner keys | `test_derive_stable_owner_key_different_info` | N/A |
| Reject stable owner key derivation in passive mode | `test_derive_stable_owner_key_rejected_in_passive_mode` | `CMB_STABLE_OWNER_KEY_NOT_AVAILABLE` |
| Generate random output through the ROM random command | `test_random_generate` | N/A |
| Reject an unknown mailbox command as fatal | `test_unknown_command_is_fatal` | `FW_PROC_MAILBOX_INVALID_COMMAND` |
| Verify mailbox command state after fatal firmware-load error | `test_mailbox_command_aborted_after_handle_fatal_error` | `FW_PROC_INVALID_IMAGE_SIZE` |
| Reject a mailbox command with an invalid checksum | `test_mailbox_invalid_checksum` | `FW_PROC_MAILBOX_INVALID_CHECKSUM` |
| Reject a mailbox request larger than the supported request size | `test_mailbox_invalid_req_size_large` | `FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH` |
| Reject a mailbox request smaller than the required request size | `test_mailbox_invalid_req_size_small` | `FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH` |
| Reject a mailbox request with zero request size | `test_mailbox_invalid_req_size_zero` | `FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH` |
| Reject use of the reserved mailbox pauser | `test_mailbox_reserved_pauser` | `FW_PROC_MAILBOX_RESERVED_PAUSER` |

## Debug Unlock, UDS/FE, and Hardware Protections

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Reject manufacturing debug unlock requests in passive mode | `test_dbg_unlock_manuf_req_in_passive_mode` | `SS_DBG_UNLOCK_REQ_IN_PASSIVE_MODE` |
| Complete manufacturing debug unlock successfully | `test_dbg_unlock_manuf_success` | N/A |
| Reject manufacturing debug unlock with the wrong mailbox command | `test_dbg_unlock_manuf_wrong_cmd` | `SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD` |
| Reject manufacturing debug unlock with an invalid token | `test_dbg_unlock_manuf_invalid_token` | N/A |
| Complete production debug unlock successfully | `test_dbg_unlock_prod_success` | N/A |
| Reject production debug unlock with an invalid request length | `test_dbg_unlock_prod_invalid_length` | N/A |
| Reject production debug unlock with an invalid token challenge | `test_dbg_unlock_prod_invalid_token_challenge` | N/A |
| Reject production debug unlock with an invalid signature | `test_dbg_unlock_prod_invalid_signature` | N/A |
| Reject production debug unlock with incorrect public keys | `test_dbg_unlock_prod_wrong_public_keys` | N/A |
| Reject production debug unlock with the wrong mailbox command | `test_dbg_unlock_prod_wrong_cmd` | `SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD` |
| Complete production debug unlock with unlock-level controls | `test_dbg_unlock_prod_unlock_levels_success` | N/A |
| Reject production debug unlock when unlock-level checks fail | `test_dbg_unlock_prod_unlock_levels_failure` | N/A |
| Reject UDS programming in passive mode | `test_uds_programming_no_active_mode` | `ROM_UDS_PROG_IN_PASSIVE_MODE` |
| Program UDS using 64-bit granularity | `test_uds_programming_granularity_64bit` | N/A |
| Program UDS with configurable status-register offset | `test_uds_programming_configurable_status_reg_offset` | N/A |
| Program UDS using 32-bit granularity | `test_uds_programming_granularity_32bit` | N/A |
| Zeroize UDS using 64-bit granularity | `test_uds_zeroization_64bit` | N/A |
| Zeroize UDS using 32-bit granularity | `test_uds_zeroization_32bit` | N/A |
| Zeroize FE partitions one at a time using 64-bit granularity | `test_zeroize_fe_partitions_one_at_a_time_64bit` | N/A |
| Zeroize FE partitions one at a time using 32-bit granularity | `test_zeroize_fe_partitions_one_at_a_time_32bit` | N/A |
| Zeroize all FE partitions in a single operation | `test_zeroize_all_partitions_single_shot` | N/A |
| Verify expected HEK seed state handling | `test_hek_seed_states` | N/A |
| Verify invalid HEK seed state handling | `test_invalid_hek_seed_state` | N/A |
| Verify PMP enforcement using a test firmware payload | `test_pmp_enforced` | N/A |
| Verify Data Vault PMP enforcement at the protected region start | `test_datavault_pmp_enforcement_region_start` | N/A |
| Verify Data Vault PMP enforcement at the protected region end | `test_datavault_pmp_enforcement_region_end` | N/A |
| Verify memcpy is not called before CFI initialization | `test_memcpy_not_called_before_cfi_init` | N/A |
| Verify FIPS test hook fatal exit behavior | `test_fips_hook_exit` | `ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT` |

## ROM Configuration, Integrity, and Test Infrastructure

| Test Scenario | Test Name | Expected Result / ROM Error Code |
| --- | --- | --- |
| Verify fake ROM can skip KAT execution | `test_skip_kats` | N/A |
| Reject fake ROM use in production when not explicitly enabled | `test_fake_rom_production_error` | `ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION` |
| Allow fake ROM behavior when production use is explicitly enabled | `test_fake_rom_production_enabled` | N/A |
| Verify fake ROM firmware-load flow | `test_fake_rom_fw_load` | N/A |
| Verify fake ROM update-reset flow | `test_fake_rom_update_reset` | N/A |
| Verify fake ROM image verification failure reporting | `test_image_verify` | `IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID` |
| Verify fake ROM version reporting | `test_fake_rom_version` | N/A |
| Verify ROM integrity failure reporting | `test_rom_integrity_failure` | `ROM_INTEGRITY_FAILURE` |
| Verify FMC can read ROM information | `test_read_rom_info_from_fmc` | N/A |
| Check that ROM does not contain Rust panic paths | `test_panic_missing` | N/A |
| Verify linker symbols match the expected memory layout | `test_linker_symbols_match_memory_layout` | N/A |
| Exercise RV32 assembly helper routines | `test_asm` | N/A |
| Verify helper log data extraction succeeds | `test_get_data` | N/A |
| Verify helper log data extraction panics when required data is absent | `test_get_data_not_found` | N/A |
