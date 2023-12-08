# **Image Validation Tests**
Test Scenario| Test Name | ROM Error Code
-----|---|---
 Check if manifest.marker is set to 0x4E414D43 	| **test_invalid_manifest_marker** | IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH
 Check if manifest.size is set to ImageManifest size 	| **test_invalid_manifest_size** | 	 IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH
 Check if vendor public key digest is not zero in the fuse_key_manifest_pk_hash fuse 	| **test_preamble_zero_vendor_pubkey_digest** | 	 IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID
 Check if the vendor public key hash from fuse matches the hash of the vendor public keys in the Preamble 	| **test_preamble_vendor_pubkey_digest_mismatch** | 	 IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH
 Check if the owner public key hash from fuse_owner_pk_hash fuse is not zero and matches the hash of the owner public key in the Preamble 	| **test_preamble_owner_pubkey_digest_mismatch** | 	 IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH
 Check revoking of key idx 0/1/2 <br> * Check that last key (idx = 3) is not revocable 	| **test_preamble_vendor_ecc_pubkey_revocation** | 	 IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED
 Check revoking of key idx 0/1/2 ..30<br> * Check if last key (idx = 31) is not revocable 	| **test_preamble_vendor_lms_pubkey_revocation** | 	 IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED
 Check vendor LMS key revocation is skipped when  lms_verify fuse is set to false	| **test_preamble_vendor_lms_optional_no_pubkey_revocation_check** | 	 Success
 Check if vendor ECC key idx is >= 4 	| **test_preamble_vendor_ecc_pubkey_out_of_bounds** | 	 IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS
 Check if vendor LMS key idx is >= 32 	| **test_preamble_vendor_lms_pubkey_out_of_bounds** | 	IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_OUT_OF_BOUNDS
 Check vendor LMS key idx validation is skipped when lms_verify fuse is set to false	| **test_preamble_vendor_lms_optional_no_pubkey_out_of_bounds_check** | 	  Success
 Check if vendor ECC public key is zero 	| **test_header_verify_vendor_sig_zero_ecc_pubkey** | 	 IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG
 Check if vendor ECC signature is zero 	| **test_header_verify_vendor_sig_zero_ecc_signature** | 	 IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG
 Check if vendor ECC signature from Preamble and computed header signature match 	| **test_header_verify_vendor_ecc_sig_mismatch** | 	 IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID
 Check if vendor LMS signature from Preamble and computed header signature match 	| **test_header_verify_vendor_lms_sig_mismatch** | 	 IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID
 Check if vendor LMS signature from Preamble validation is skipped when lms_verify fuse is set to false	| **test_header_verify_vendor_lms_optional_no_sig_mismatch_check** | 	 Success
 Check if owner LMS signature from Preamble and computed header signature match 	| **test_header_verify_owner_lms_sig_mismatch** | 	 IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID
 Check if owner LMS signature from Preamble validation is skipped when lms_verify fuse is set to false	| **test_header_verify_owner_lms_optional_no_sig_mismatch_check** | 	 Success
 Check if the vendor ECC public key index in Preamble and Header match 	| **test_header_verify_vendor_ecc_pub_key_in_preamble_and_header** | 	 IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH
 Check if the vendor LMS public key index in Preamble and Header match 	| **test_header_verify_vendor_lms_pub_key_in_preamble_and_header** | 	 IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH
Check if the vendor LMS public key index validation is skipped when lms_verify fuse is set to false	| **test_header_verify_vendor_lms_optional_no_pub_key_in_preamble_and_header_check** | 	 Success
 Check if the owner ECC public key.x in Preamble is zero 	| **test_header_verify_owner_ecc_sig_zero_pubkey_x** | 	IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG
 Check if the owner ECC public key.y in Preamble is zero 	| **test_header_verify_owner_ecc_sig_zero_pubkey_y** | 	IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG
 Check if the owner ECC signature.r in Preamble is zero 	| **test_header_verify_owner_ecc_sig_zero_signature_r** | 	 IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG
 Check if the owner ECC signature.s in Preamble is zero 	| **test_header_verify_owner_ecc_sig_zero_signature_s** | 	 IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG
 Check if owner ECC signature.r from Preamble and computed header signature match 	| **test_header_verify_owner_ecc_sig_invalid_signature_r** | 	 IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID
 Check if owner ECC signature.s from Preamble and computed header signature match 	| **test_header_verify_owner_ecc_sig_invalid_signature_s** | 	 IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID
 Check if header.toc_count equals MAX_TOC_ENTRY_COUNT (2) 	| **test_toc_invalid_entry_count** | 	 IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID
 Check if digest of [manifest.fmc_toc manifest.rt_toc] matches header.toc_digest 	| **test_toc_invalid_toc_digest** | 	 IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH
 Check if FMC size if zero 	| **test_toc_fmc_size_zero** | 	 IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO
 Check if FMC and Runtime images overlap in the image bundle 	| **test_toc_fmc_range_overlap** | 	 IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP
 Check if FMC image is before Runtime image in the image bundle 	| **test_toc_fmc_range_incorrect_order** | 	 IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER
 Check if FMC and Runtime image load address range overlap 	| **test_fmc_rt_load_address_range_overlap** | 	 IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP
 Check if manifest.fmc_toc.digest matches FMC image digest 	| **test_fmc_digest_mismatch** | 	 IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH
 Check if FMC load address is within ICCM range 	| **test_fmc_invalid_load_addr_before_iccm** | 	 IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID
 Check if FMC load address is within ICCM range 	| **test_fmc_invalid_load_addr_after_iccm** | 	 IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID
 Check if FMC is fully contained in the ICCM 	| **test_fmc_not_contained_in_iccm** | 	 IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID
 Check if FMC load address is DWORD aligned 	| **test_fmc_load_addr_unaligned** | 	 IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED
 Check if FMC entry point is within ICCM range  	| **test_fmc_invalid_entry_point_before_iccm** | 	 IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID
 Check if FMC entry point is within ICCM range  	| **test_fmc_invalid_entry_point_after_iccm** | 	 IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID
 Check if FMC entry point is DWORD aligned 	| **test_fmc_entry_point_unaligned** | 	 IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED
 Check if FMC SVN is greater than max (32) 	| **test_fmc_svn_greater_than_32** | 	 IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED
 Check if FMC SVN is less than toc_fmc.min_svn 	| **test_fmc_svn_less_than_min_svn** | 	 IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED
 Check if FMC SVN is less than fuse svn 	| **test_fmc_svn_less_than_fuse_svn** | 	 IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE
 Check if RT size if 0 	| **test_toc_rt_size_zero** | 	 IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO
 Check if manifest.rt_toc.digest matches Runtime image digest 	| **test_runtime_digest_mismatch** | 	 IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH
 Check if RT load address is within ICCM range 	| **test_runtime_invalid_load_addr_before_iccm** | 	 IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID
 Check if RT load address is within ICCM range 	| **test_runtime_invalid_load_addr_after_iccm** | 	 IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID
 Check if RT is fully contained in the ICCM 	| **test_runtime_not_contained_in_iccm** | 	 IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID
 Check if RT load address is DWORD aligned 	| **test_runtime_load_addr_unaligned** | 	 IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED
 Check if RT entry point is within ICCM range  	| **test_runtime_invalid_entry_point_before_iccm** | 	 IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID
 Check if RT entry point is within ICCM range  	| **test_runtime_invalid_entry_point_after_iccm** | 	 IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID
 Check if RT entry point is DWORD aligned 	| **test_runtime_entry_point_unaligned** | 	 IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED
 Check if RT SVN is greater than max (128) 	| **test_runtime_svn_greater_than_max** | 	 IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED
 Check if RT SVN is less than toc_rt.min_svn 	| **test_runtime_svn_less_than_min_svn** | 	 IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED
 Check if RT SVN is less than fuse svn 	| **test_runtime_svn_less_than_fuse_svn** | 	 IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE
 Generates the LDEVID and FMC Alias certificates |**cert_test** | 	 N/A
 Check if the owner and vendor cert validty dates are present in FMC Alias cert | **cert_test_with_custom_dates** | 	 N/A

<br><br>
# **COLD BOOT Tests**
Test Scenario| Test Name | ROM Error Code
---|---|---
Tests with X509KeyIdAlgo::[SHA1/SHA256/SHA384/Fuse] for generating  IDEVID Subject Key Identifier | **test_idev_subj_key_id_algo**  | N/A
Requests CSR and downloads the CSR  | **test_generate_csr**  | N/A
Check value in ColdResetEntry4::RomColdBootStatus datavault register | **test_check_rom_cold_boot_status_reg**   | N/A
Check if entries are correctly added in Firmware Handoff table | **test_fht_info**   | N/A
Check if LMS Vendor PubKey Index in datavault is 0xFFFFFFFF when LMS verification is not enabled | **test_check_no_lms_info_in_datavault_on_lms_unavailable**   | N/A
Check if boot statuses are correctly reported | **test_cold_reset_status_reporting** | N/A
Stress test: Boot caliptra 1000 times with a different UDS identity each time, and confirm generated certs are valid. This should expose x509 serialization bugs. |**test_generate_csr_stress** | N/A

<br><br>
# **Firmware Downloader Tests**
Test Scenario| Test Name | ROM Error Code
---|---|---
Check if firmware is zero-sized | **test_zero_firmware_size** | FW_PROC_INVALID_IMAGE_SIZE
Check if firmware is not more than max. size (128K) | **test_firmware_gt_max_size**  | FW_PROC_INVALID_IMAGE_SIZE
Check if PCR log entries are correctly logged to DCCM | **test_pcr_log**   | N/A
Check PCR log entries - No Onwer Public Key Hash in fuse_owner_pk_hash | **test_pcr_log_no_owner_key_digest_fuse**   | N/A
Check PCR log entries - FMC Fuse SVN set in fuse_fmc_key_manifest_svn | **test_pcr_log_fmc_fuse_svn**   | N/A
Check PCR log entries across Update Reset | **test_pcr_log_across_update_reset**   | N/A
Check if Fuse log entries are correctly logged to DCCM | **test_fuse_log**   | N/A

<br><br>


# **Mailbox Command Tests**
Test Scenario| Test Name | ROM Error Code
---|---|---
Check uploading a single measurement | **test_upload_single_measurement**   | N/A
Check uploading measurements more than supported limit | **test_upload_measurement_limit**   | N/A
Check uploading no measurements | **test_upload_no_measurement**   | N/A
Check for sending invalid commands to the mailbox | **test_unknown_command_is_fatal** | FW_PROC_MAILBOX_INVALID_COMMAND
Check for sending an invalid fw image followed by a valid one | **test_mailbox_command_aborted_after_handle_fatal_error** | FW_PROC_INVALID_IMAGE_SIZE
Check for failure by sending STASH_MEASUREMENT command with invalid Checkum | **test_mailbox_invalid_Checkum** | FW_PROC_MAILBOX_INVALID_CheckUM
Check for failure by sending STASH_MEASUREMENT command with greater than supported size | **test_mailbox_invalid_req_size_large** | FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH
Check for failure by sending CAPABILITIES command with zero size | **test_mailbox_invalid_req_size_zero** | FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH

<br><br>

# **Update Reset Tests**
Test Scenario| Test Name | ROM Error Code
---|---|---
Tests successful Update Reset flow  | **test_update_reset_success** | N/A
Tests update reset flow by not providing firmware image  | **test_update_reset_no_mailbox_cmd** | ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE
Tests update reset flow by providing a non-fw load Mailbox command  | **test_update_reset_non_fw_load_cmd** | ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND
Tests update reset flow by providing non-compliant fw image   | **test_update_reset_verify_image_failure** | IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH
Check if boot statuses are correctly reported | **test_update_reset_boot_status** | N/A
Tests update reset flow by providing a different vendor ECC public key index in the image  | **test_update_reset_vendor_ecc_pub_key_idx_dv_mismatch** |IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH
Tests update reset flow by providing a different vendor LMS public key index in the image | **test_update_reset_vendor_lms_pub_key_idx_dv_mismatch** | IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_LMS_PUB_KEY_IDX_MISMATCH
Check value in WarmResetEntry4::RomUpdateResetStatus datavault register | **test_check_rom_update_reset_status_reg**   | N/A
Ensure that hitless update flow can update an entire 128k bundle with completely different ICCM contents than original boot | **test_update_reset_max_fw_image** | N/A
<br><br>

# **Warm Reset Tests**
Test Scenario| Test Name | ROM Error Code
---|---|---
Tests successful Warm Reset flow  | **test_warm_reset_success** | N/A
Tests Warm Reset flow during cold boot, before image validation | **test_warm_reset_during_cold_boot_before_image_validation** | ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET
Tests Warm Reset flow during cold boot, during image validation | **test_warm_reset_during_cold_boot_during_image_validation** | ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET
Tests Warm Reset flow during cold boot, after image validation | **test_warm_reset_during_cold_boot_after_image_validation** | ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET
Tests Warm Reset flow during update reset | **test_warm_reset_during_update_resetn** | ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET
<br><br>

# **General Integration Tests**
Test Scenario| Test Name | ROM Error Code
---|---|---
Check for any RUST panics added to the code | **test_panic_missing** | N/A
Checks that extended error info is populated correctly upon watchdog timer timeout | **test_rom_wdt_timeout** | ROM_GLOBAL_WDT_EXPIRED
Triggers a CPU fault and checks that extended error info is populated correctly | **test_cpu_fault** | ROM_GLOBAL_EXCEPTION
Ensure that boot ROM can load a 128k bundle into ICCM (assert ICCM contents in test) |**test_max_fw_image** | N/A

# **Test Gaps**
Test Scenario| Test Name | ROM Error Code
---|---|---
Expand `smoke_test` to perform a hitless update and confirm everything is mixed into the identity correctly. | N/A | N/A
Ensure that hitless update flow can update an entire 128k bundle with completely different ICCM contents than original boot | N/A | N/A
Run all the tests against the prod ROM (no logging) | N/A | N/A
