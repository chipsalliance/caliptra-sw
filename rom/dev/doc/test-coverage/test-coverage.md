# **Image Validation Integration Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_invalid_manifest_marker**| Image Verification - Manifest | Checks if manifest.marker is set to 0x4E414D43 | IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH
**test_invalid_manifest_size** | Image Verification - Manifest | Checks if manifest.size is set to ImageManifest size | IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH
**test_preamble_zero_vendor_pubkey_digest** | Image Verification - Preamble | Checks if vendor public key digest is not zero in the fuse | IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID
**test_preamble_vendor_pubkey_digest_mismatch** | Image Verification - Preamble | Checks if the vendor public key hash from fuse matches the hash of the vendor public keys in the Preamble | IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH
**test_preamble_owner_pubkey_digest_mismatch** | Image Verification - Preamble | Checks if the owner public key hash from fuse is not zero and matches the hash of the owner public key in the Preamble | IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH
**test_preamble_vendor_ecc_pubkey_revocation** | Image Verification - Preamble | Checks revoking of key idx 0/1/2 <br> * Checks if last key (idx = 3) is revocable | IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED
**test_preamble_vendor_lms_pubkey_revocation** | Image Verification - Preamble | Checks revoking of key idx 0/1/2 <br> * Checks if last key (idx = 3) is revocable | IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED
**test_preamble_vendor_lms_optional_no_pubkey_revocation_check** | Image Verification - Preamble | * Sets lms_verify fuse to false and checks vendor LMS key revocation | Success
**test_preamble_vendor_ecc_pubkey_out_of_bounds** | Image Verification - Preamble | Checks if vendor ECC key idx is >= 4 | IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS
**test_preamble_vendor_lms_pubkey_out_of_bounds** | Image Verification - Preamble | Checks if vendor LMS key idx is >= 4 | 
IMAGE_VERIFIER_ERR_VENDOR_LMS_PUBKEY_INDEX_OUT_OF_BOUNDS
**test_preamble_vendor_lms_optional_no_pubkey_out_of_bounds_check** | Image Verification - Preamble | Sets lms_verify fuse to false and checks if vendor LMS key idx is >= 4 |  Success
IMAGE_VERIFIER_ERR_VENDOR_LMS_PUBKEY_INDEX_OUT_OF_BOUNDS
**test_preamble_owner_lms_pubkey_out_of_bounds** | Image Verification - Preamble | Checks if LMS key idx is >= 4 | IMAGE_VERIFIER_ERR_OWNER_LMS_PUBKEY_INDEX_OUT_OF_BOUNDS
**test_preamble_owner_lms_optional_no_pubkey_out_of_bounds_check** | Image Verification - Preamble | Sets lms_verify fuse to false and checks if owner LMS key idx is >= 4 | Success
**test_header_verify_vendor_sig_zero_ecc_pubkey** | Image Verification - Header | Checks if vendor ECC public key is non-zero | IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG
**test_header_verify_vendor_sig_zero_ecc_signature** | Image Verification - Header | Checks if vendor signature is non-zero | IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG
**test_header_verify_vendor_ecc_sig_mismatch** | Image Verification - Header | Checks if vendor ECC signature from Preamble and computed header signature match | IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID
**test_header_verify_vendor_lms_sig_mismatch** | Image Verification - Header | Checks if vendor LMS signature from Preamble and computed header signature match | IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID
**test_header_verify_vendor_lms_optional_no_sig_mismatch_check** | Image Verification - Header | Sets lms_verify fuse to false and checks if vendor LMS signature from Preamble and computed header signature match | Success
**test_header_verify_owner_lms_sig_mismatch** | Image Verification - Header | Checks if owner LMS signature from Preamble and computed header signature match | IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID
**test_header_verify_owner_lms_optional_no_sig_mismatch_check** | Image Verification - Header | Sets lms_verify fuse to false and checks if owner LMS signature from Preamble and computed header signature match | Success
**test_header_verify_vendor_ecc_pub_key_in_preamble_and_header** | Image Verification - Header | Checks if the vendor ECC public key index in Preamble and Header match | IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH
**test_header_verify_vendor_lms_pub_key_in_preamble_and_header** | Image Verification - Header | Checks if the vendor LMS public key index in Preamble and Header match | IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH
**test_header_verify_vendor_lms_optional_no_pub_key_in_preamble_and_header_check** | Image Verification - Header |  Sets lms_verify fuse to false and checks if the vendor LMS public key index in Preamble and Header match | Success
**test_header_verify_owner_lms_pub_key_in_preamble_and_header** | Image Verification - Header | Checks if the owner LMS public key index in Preamble and Header match | IMAGE_VERIFIER_ERR_OWNER_LMS_PUB_KEY_INDEX_MISMATCH
**test_header_verify_owner_lms_optional_no_pub_key_in_preamble_and_header_check** | Image Verification - Header | Sets lms_verify fuse to false and checks if the owner LMS public key index in Preamble and Header match | Success
**test_header_verify_owner_sig_zero_fuses_zero_pubkey_x** | Image Verification - Header | Checks if the owner ECC public key in Preamble is zero | IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_INVALID_ARG
**test_header_verify_owner_ecc_sig_zero_pubkey_x** | Image Verification - Header | Checks if the owner ECC public key.x in Preamble is zero | IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_INVALID_ARG
**test_header_verify_owner_ecc_sig_zero_pubkey_y** | Image Verification - Header | Checks if the owner ECC public key.y in Preamble is zero | IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_INVALID_ARG
**test_header_verify_owner_ecc_sig_zero_signature_r** | Image Verification - Header | Checks if the owner ECC signature.r in Preamble is zero | IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG
**test_header_verify_owner_ecc_sig_zero_signature_s** | Image Verification - Header | Checks if the owner ECC signature.s in Preamble is zero | IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG
**test_header_verify_owner_ecc_sig_invalid_signature_r** | Image Verification - Header | Checks if owner ECC signature.r from Preamble and computed header signature match | IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID
**test_header_verify_owner_ecc_sig_invalid_signature_s** | Image Verification - Header | Checks if owner ECC signature.s from Preamble and computed header signature match | IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID
**test_toc_invalid_entry_count** | Image Verification - TOC | Checks if header.toc_count equals MAX_TOC_ENTRY_COUNT (2) | IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID
**test_toc_invalid_toc_digest** | Image Verification - TOC | Checks if digest of [manifest.fmc_toc | manifest.rt_toc] matches header.toc_digest | IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH
**test_toc_fmc_range_overlap** | Image Verification - TOC | Checks if FMC and Runtime images don't overlap in the image bundle | IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP
**test_toc_fmc_range_incorrect_order** | Image Verification - TOC | Checks if FMC image is before Runtime image in the image bundle | IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER
**test_fmc_rt_load_address_range_overlap** | Image Verification - TOC | Checks if FMC and Runtime image load address range don't overlap | IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP
**test_fmc_digest_mismatch** | Image Verification - FMC | Checks if manifest.fmc_toc.digest matches FMC image digest | IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH
**test_fmc_invalid_load_addr_before_iccm** | Image Verification - FMC | Checks if FMC load address is within ICCM range | IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID
**test_fmc_invalid_load_addr_after_iccm** | Image Verification - FMC | Checks if FMC load address is within ICCM range | IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID
**test_fmc_load_addr_unaligned** | Image Verification - FMC | Checks if FMC load address is DWORD aligned | IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED
**test_fmc_invalid_entry_point_before_iccm** | Image Verification - FMC | Checks if FMC entry point is within ICCM range  | IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID
**test_fmc_invalid_entry_point_after_iccm** | Image Verification - FMC | Checks if FMC entry point is within ICCM range  | IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID
**test_fmc_entry_point_unaligned** | Image Verification - FMC | Checks if FMC entry point is DWORD aligned | IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED
**test_fmc_svn_greater_than_32** | Image Verification - FMC | Checks if FMC SVN is greater than max (32) | IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED
**test_fmc_svn_less_than_min_svn** | Image Verification - FMC | Checks if FMC SVN is less than toc_fmc.min_svn | IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED
**test_fmc_svn_less_than_fuse_svn** | Image Verification - FMC | Checks if FMC SVN is less than fuse svn | IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE
**test_runtime_digest_mismatch** | Image Verification - RT | Checks if manifest.rt_toc.digest matches Runtime image digest | IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH
**test_runtime_invalid_load_addr_before_iccm** | Image Verification - RT | Checks if RT load address is within ICCM range | IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID
**test_runtime_invalid_load_addr_after_iccm** | Image Verification - RT | Checks if RT load address is within ICCM range | IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID
**test_runtime_load_addr_unaligned** | Image Verification - RT | Checks if RT load address is DWORD aligned | IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED
**test_runtime_invalid_entry_point_before_iccm** | Image Verification - RT | Checks if RT entry point is within ICCM range  | IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID
**test_runtime_invalid_entry_point_after_iccm** | Image Verification - RT | Checks if RT entry point is within ICCM range  | IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID
**test_runtime_entry_point_unaligned** | Image Verification - RT | Checks if RT entry point is DWORD aligned | IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED
**test_runtime_svn_greater_than_max** | Image Verification - RT | Checks if RT SVN is greater than max (128) | IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED
**test_runtime_svn_less_than_min_svn** | Image Verification - RT | Checks if RT SVN is less than toc_rt.min_svn | IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED
**test_runtime_svn_less_than_fuse_svn** | Image Verification - RT | Checks if RT SVN is less than fuse svn | IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE
**cert_test** | DICE Cert | <Placeholder> | N/A
**cert_test_with_custom_dates** | DICE Cert | <Placeholder> | N/A
<br><br>
# **COLD BOOT Tests**
## **IDEVID Integration Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_idev_subj_key_id_algo** | DICE - IDEVID | Tests with X509KeyIdAlgo::[SHA1/SHA256/SHA384/Fuse] for generating  Subject Key Identifier | N/A
**test_generate_csr** | DICE - IDEVID | * Requests CSR generation<br>* Downloads the CSR  | N/A
<br><br>
# **Firmware Downloader Integration Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_zero_firmware_size** | FW Downloader | Checks if firmware is zero-sized | FW_PROC_INVALID_IMAGE_SIZE
**test_firmware_gt_max_size** | FW Downloader |  Checks if firmware is not more than max. size (128K)  | FW_PROC_INVALID_IMAGE_SIZE
**test_pcr_log** | FW Downloader |  Checks if PCR log entries are correctly logged to DCCM  | N/A
**ttest_fuse_log** | FW Downloader |  Checks if Fuse log entries are correctly logged to DCCM  | N/A
<br><br>
## **FMCALIAS Integration Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_fht_info** | DICE - FMCALIAS | Checks if entries are correctly added in Firmware Handoff table | N/A
<br><br>
## **DICE E2E Integration Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_status_reporting** | All layers | Checks if boot statuses are correctly reported | N/A
<br><br>
# **Update Reset Tests**
Test Name |  Description | ROM Error Code
---|---|---
**test_update_reset_success** | Tests successful Update Reset flow  | N/A
**test_update_reset_no_mailbox_cmd** | Tests update reset flow by not providing firmware image  | ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE
**test_update_reset_non_fw_load_cmd** | Tests update reset flow by providing a non-fw load Mailbox command  | ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND
**test_update_reset_verify_image_failure** | Tests update reset flow by providing non-compliant fw image  | IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH
<br><br>
# **Mailbox Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_unknown_command_is_not_fatal** | FW Downloader | Checks for sending invalid commands to the mailbox | N/A
**test_mailbox_command_aborted_after_handle_fatal_error** | FW Downloader | Checks for sending an invalid fw image followed by a valid one | FW_PROC_INVALID_IMAGE_SIZE
<br><br>
# **General Integration Tests**
Test Name | ROM Stage | Description | ROM Error Code
---|---|---|---
**test_panic_missing** | All layers | Checks for any RUST panics added to the code | N/A
