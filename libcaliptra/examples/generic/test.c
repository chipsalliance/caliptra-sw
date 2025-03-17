// Licensed under the Apache-2.0 license
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"
#include "caliptra_api.h"
#include "caliptra_enums.h"
#include "caliptra_if.h"
#include "caliptra_types.h"
#include "idev_csr_array.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// Arbitrary example only - values must be customized/tuned for the SoC
static const uint64_t wdt_timeout = 0xA0000000;         // approximately 5s for 500MHz clock
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint16_t itrng_entropy_low_threshold = 0x1;
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint16_t itrng_entropy_high_threshold = 0xFFFF;
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint16_t itrng_entropy_repetition_count = 0xFFFF;

// Exists for testbench only - not part of interface for actual implementation
extern void testbench_reinit(void);
void hwmod_init(struct caliptra_buffer rom, const test_info *info);

#ifdef ENABLE_DEBUG
// Exists for testbench only - not part of interface for actual implementation
static int dump_array_to_file(struct caliptra_buffer* buffer, const char *filename);
#endif

/*
* caliptra_csr_is_ready
*
* Waits forever for the CSR to be ready
*
* @return bool True if ready, false otherwise
*/
static void caliptra_wait_for_csr_ready(void)
{
    while (true)
    {
        if (caliptra_is_idevid_csr_ready()) {
            break;
        }
        caliptra_wait();
     }
}

/*
 * caliptra_verify_signature
 *
 * Uses OpenSSL to verify that the signature returned by `SignWithExportedEcdsa`
 * matches the public key in the certificate vended by `DeriveContext`
 *
 * @return bool True if the signature passes verification, false otherwise
 */
static bool caliptra_verify_ecdsa_signature_helper(struct dpe_derive_context_exported_cdi_response* dpe_resp, struct caliptra_sign_with_exported_ecdsa_resp* sign_resp, uint8_t* tbs, size_t tbs_size)
{
    bool status = true;

    EVP_PKEY* pkey = NULL;
    EC_KEY *ec_pub_key = NULL, *ecdsa_key = NULL;
    BIGNUM *r = NULL, *s = NULL, *x = NULL, *y = NULL;
    ECDSA_SIG* signature = NULL;
    EC_POINT* point = NULL;
    uint8_t* dersig = NULL;
    BN_CTX* bn_ctx = NULL;
    X509* x509 = NULL;
    BIO* cert_ptr =
        BIO_new_mem_buf(dpe_resp->new_certificate, dpe_resp->certificate_size);

    if (cert_ptr == NULL) {
        printf("Error creating certificate pointer.\n");
        status = false;
        goto cleanup;
    }

    x509 = d2i_X509_bio(cert_ptr, NULL);

    if (x509 == NULL) {
        printf("Error parsing certificate.\n");
        status = false;
        goto cleanup;
    }

    pkey = X509_get_pubkey(x509);
    if (pkey == NULL) {
        printf("Error getting public key.\n");
        status = false;
        goto cleanup;
    }

    ec_pub_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (ec_pub_key == NULL) {
        printf("Error converting pub key to EC pub key.\n");
        status = false;
        goto cleanup;
    }

    r = BN_bin2bn(sign_resp->signature_r, 48, NULL);
    if (r == NULL) {
        printf("Error creating ECDSA R.\n");
        status = false;
        goto cleanup;
    }

    s = BN_bin2bn(sign_resp->signature_s, 48, NULL);
    if (s == NULL) {
        printf("Error creating ECDSA S.\n");
        status = false;
        goto cleanup;
    }

    signature = ECDSA_SIG_new();
    if (signature == NULL) {
        printf("Error creating signature.\n");
        status = false;
        goto cleanup;
    }
    ECDSA_SIG_set0(signature, r, s);

    int size = i2d_ECDSA_SIG(signature, &dersig);

    if (ECDSA_verify(0, (const unsigned char *)tbs, tbs_size, dersig, size, ec_pub_key) != 1) {
      status = false;
      goto cleanup;
    }

    x = BN_bin2bn(sign_resp->derived_public_key_x, 48, NULL);
    if (x == NULL) {
      printf("Error creating ECDSA X.\n");
      status = false;
      goto cleanup;
    }

    y = BN_bin2bn(sign_resp->derived_public_key_y, 48, NULL);
    if (y == NULL) {
      printf("Error creating ECDSA Y.\n");
      status = false;
      goto cleanup;
    }

    ecdsa_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (ecdsa_key == NULL) {
        printf("Error creating ECDSA public key.\n");
        status = false;
        goto cleanup;
    }

    point = EC_POINT_new(EC_KEY_get0_group(ecdsa_key));
    if (point == NULL) {
        printf("Error creating EC point.\n");
        status = false;
        goto cleanup;
    }

    bn_ctx = BN_CTX_new();
    if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ecdsa_key),
                                             point, x, y, bn_ctx)) {
      printf("Error setting EC point coordinates.\n");
      status = false;
      goto cleanup;
    }
    if (!EC_KEY_set_public_key(ecdsa_key, point)) {
        printf("Error setting public key.\n");
        status = false;
        goto cleanup;
    }

    if (ECDSA_verify(0, (const unsigned char *)tbs, tbs_size, dersig, size, ecdsa_key) != 1) {
      status = false;
      goto cleanup;
    }

cleanup:
    // r and s are freed in ECDSA_SIG_free(signature)
    BN_CTX_free(bn_ctx);
    EC_POINT_free(point);
    EC_KEY_free(ecdsa_key);
    BN_clear_free(y);
    BN_clear_free(x);
    OPENSSL_free(dersig);
    ECDSA_SIG_free(signature);
    EC_KEY_free(ec_pub_key);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    BIO_free(cert_ptr);

    return status;
}

static bool caliptra_verify_ecdsa_signature(struct dpe_derive_context_exported_cdi_response* dpe_resp)
{
    struct caliptra_sign_with_exported_ecdsa_req sign_req = { 0 };
    struct caliptra_sign_with_exported_ecdsa_resp sign_resp = { 0 };

    // SHA384 of a 48 bytes of 0s
    uint8_t tbs[] = {
        0x8f, 0x0d, 0x14, 0x5c, 0x03, 0x68, 0xad, 0x6b, 0x70, 0xbe,
        0x22, 0xe4, 0x1c, 0x40, 0x0e, 0xea, 0x91, 0xb9, 0x71, 0xd9,
        0x6b, 0xa2, 0x20, 0xfe, 0xc9, 0xfa, 0xe2, 0x5a, 0x58, 0xdf,
        0xfd, 0xaa, 0xf7, 0x2d, 0xbe, 0x8f, 0x67, 0x83, 0xd5, 0x51,
        0x28, 0xc9, 0xdf, 0x4e, 0xfa, 0xf6, 0xf8, 0xa7
    };

    memcpy(&sign_req.exported_cdi_handle, dpe_resp->exported_cdi_handle, sizeof(dpe_resp->exported_cdi_handle));
    memcpy(&sign_req.tbs, &tbs, sizeof(tbs));

    int status = caliptra_sign_with_exported_ecdsa(&sign_req, &sign_resp, false);

    if (status) {
        printf("Sign with exported Ecdsa failed: 0x%x\n", status);
        return false;
    }

    return caliptra_verify_ecdsa_signature_helper(dpe_resp, &sign_resp, tbs, sizeof(tbs));
}

void dump_caliptra_error_codes()
{
    printf("Caliptra FW error non-fatal code is 0x%x\n", caliptra_read_fw_non_fatal_error());
    printf("Caliptra FW error fatal code is 0x%x\n", caliptra_read_fw_fatal_error());
}

static int derive_context(struct dpe_derive_context_response *out, int flags) 
{
    struct caliptra_invoke_dpe_req dpe_req = { 0 };
    struct caliptra_invoke_dpe_resp dpe_resp = { 0 };
    struct dpe_derive_context_cmd derive_context_cmd = { 0 };

    derive_context_cmd.cmd_hdr.magic = DPE_MAGIC;
    derive_context_cmd.cmd_hdr.magic = DPE_MAGIC;
    derive_context_cmd.cmd_hdr.cmd_id = DPE_DERIVE_CONTEXT;
    derive_context_cmd.cmd_hdr.profile = 0x4;
    derive_context_cmd.flags = flags;

    memset(&dpe_req, 0, sizeof(struct caliptra_invoke_dpe_req));
    dpe_req.derive_context_cmd = derive_context_cmd;
    dpe_req.data_size = sizeof(struct dpe_derive_context_cmd);

    int status = caliptra_invoke_dpe_command(&dpe_req, &dpe_resp, false);
    if (status) {
        printf("DPE Command failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        return 1;
    } else {
        memcpy(out, &dpe_resp.derive_context_resp, sizeof(struct dpe_derive_context_response));
        printf("DPE Command: OK\n");
    }

    return 0;
}

static int derive_context_exported_cdi(struct dpe_derive_context_exported_cdi_response *out, int flags) 
{
    struct caliptra_invoke_dpe_req dpe_req = { 0 };
    struct caliptra_invoke_dpe_resp dpe_resp = { 0 };
    struct dpe_derive_context_cmd derive_context_cmd = { 0 };

    derive_context_cmd.cmd_hdr.magic = DPE_MAGIC;
    derive_context_cmd.cmd_hdr.magic = DPE_MAGIC;
    derive_context_cmd.cmd_hdr.cmd_id = DPE_DERIVE_CONTEXT;
    derive_context_cmd.cmd_hdr.profile = 0x4;
    derive_context_cmd.flags = flags;

    memset(&dpe_req, 0, sizeof(struct caliptra_invoke_dpe_req));
    dpe_req.derive_context_cmd = derive_context_cmd;
    dpe_req.data_size = sizeof(struct dpe_derive_context_cmd);

    int status = caliptra_invoke_dpe_command(&dpe_req, &dpe_resp, false);
    if (status) {
        printf("DPE Command failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        return 1;
    } else {
        memcpy(out, &dpe_resp.derive_context_exported_cdi_resp, sizeof(struct dpe_derive_context_exported_cdi_response));
        printf("DPE Command: OK\n");
    }

    return 0;
}

int boot_to_ready_for_fw(const test_info* info, bool req_idev_csr)
{
    int status;

    if (!info) {
        printf("Failed to boot Caliptra, test_info is null\n");
        return INVALID_PARAMS;
    }

    // Initialize FSM GO
    caliptra_bootfsm_go();

    // Request CSR if needed
    if (req_idev_csr)
    {
       caliptra_req_idev_csr_start();
    }

    caliptra_set_wdt_timeout(wdt_timeout);

    caliptra_configure_itrng_entropy(itrng_entropy_low_threshold,
                                     itrng_entropy_high_threshold,
                                     itrng_entropy_repetition_count);

    // Set up our PAUSER value for the mailbox regs
    status = caliptra_mbox_pauser_set_and_lock(info->apb_pauser);
    if (status) {
        printf("Set MBOX pauser Failed: 0x%x\n", status);
        return status;
    }

    // Set up our PAUSER value for the fuse regs
    status = caliptra_fuse_pauser_set_and_lock(info->apb_pauser);
    if (status) {
        printf("Set FUSE pauser Failed: 0x%x\n", status);
        return status;
    }

    if ((status = caliptra_init_fuses(&info->fuses)) != 0) {
      printf("Failed to init fuses: %d\n", status);
      return status;
    }

    if (req_idev_csr == false)
    {
        // Wait until ready for FW
        caliptra_ready_for_firmware();
    }

    return status;
}

int legacy_boot_test(const test_info* info)
{
    int failure = 0;
    int status = boot_to_ready_for_fw(info, false);

    if (status){
        failure = 1;
    }

    // Load Image Bundle
    // FW_PATH is defined on the compiler command line
    status = caliptra_upload_fw(&info->image_bundle, false);

    if (status)
    {
        printf("FW Load Failed: 0x%x\n", status);
        failure = 1;
    } else {
        printf("FW Load: OK\n");
    }

    // Send a FIPS version command in async mode
    struct caliptra_fips_version_resp version;
    // Send async
    status = caliptra_fips_version(&version, true);

    if (status) {
        printf("Get FIPS Version send failed: 0x%x\n", status);
        failure = 1;
    } else {
        // Wait indefinitely for completion
        while (!caliptra_test_for_completion()){
            caliptra_wait();
        }

        status = caliptra_complete();
    }

    if (status)
    {
        printf("Get FIPS Version failed: 0x%x\n", status);
        failure = 1;
    }
    else
    {
        int last_char = sizeof(version.name) - 1;
        version.name[last_char] = 0;
        printf("FIPS_VERSION = mode: 0x%x, fips_rev (0x%x, 0x%x, 0x%x), name %s \n", version.mode,
            version.fips_rev[0], version.fips_rev[1], version.fips_rev[2], version.name);
    }

    // Send a stash measurement command with async off
    // Need some representative values for these, see below.
    struct caliptra_stash_measurement_req r = {0};
    struct caliptra_stash_measurement_resp c = {0};

    status = caliptra_stash_measurement(&r, &c, false);

    if (status) {
        printf("Stash measurement failed: 0x%x\n", status);
        failure = 1;
    } else {
        printf("Stash measurement: OK\n");
    }

    return failure;
}

// Issue every ROM command
// Intent is just to make sure ROM accepts the command ID and the payload
// Not attempting to actually test command functionality
int rom_test_all_commands(const test_info* info)
{
    int failure = 0;
    int status = boot_to_ready_for_fw(info, false);

    if (status){
        dump_caliptra_error_codes();
        failure = 1;
    }

    // NOTE: Response structs are uninitialized to confirm libcaliptra handles this properly
    // STASH_MEASUREMENT
    struct caliptra_stash_measurement_req stash_req = {};
    struct caliptra_stash_measurement_resp stash_resp;

    status = caliptra_stash_measurement(&stash_req, &stash_resp, false);

    if (status) {
        printf("Stash Measurement failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Stash Measurement: OK\n");
    }

    // CAPABILITIES
    struct caliptra_capabilities_resp cap_resp;

    status = caliptra_capabilities(&cap_resp, false);

    if (status) {
        printf("Capabilities failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Capabilities: OK\n");
    }

    // FIPS_VERSION
    struct caliptra_fips_version_resp version_resp;

    status = caliptra_fips_version(&version_resp, false);

    if (status) {
        printf("FIPS Version failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Version: OK\n");
    }

    // SELF_TEST_START
    status = caliptra_self_test_start(false);

    if (status) {
        printf("FIPS Self Test Start failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Self Test Start: OK\n");
    }

    // SELF_TEST_GET_RESULTS
    status = caliptra_self_test_get_results(false);

    if (status) {
        printf("FIPS Self Test Get Results failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Self Test Get Results: OK\n");
    }

    // SHUTDOWN
    status = caliptra_shutdown(false);

    if (status) {
        printf("FIPS Shutdown failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Shutdown: OK\n");
    }

    return failure;
}

// Issue every runtime command
// Intent is just to make sure FW accepts the command ID and the payload
// Not attempting to actually test command functionality
int rt_test_all_commands(const test_info* info)
{
    int failure = 0;
    uint32_t non_fatal_error;
    int status = boot_to_ready_for_fw(info, false);

    if (status){
        failure = 1;
    }

    // NOTE: Response structs are uninitialized to confirm libcaliptra handles this properly
    // Load Image Bundle
    // FW_PATH is defined on the compiler command line
    status = caliptra_upload_fw(&info->image_bundle, false);

    if (status)
    {
        printf("FW Load Failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FW Load: OK\n");
    }

    status = caliptra_ready_for_runtime();
    if (status) {
        printf("Firmware Boot Failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    }

    // GET_IDEV_CERT
    struct caliptra_get_idev_cert_req idev_cert_req = {};
    struct caliptra_get_idev_cert_resp idev_cert_resp;

    status = caliptra_get_idev_cert(&idev_cert_req, &idev_cert_resp, false);

    if (status) {
        printf("Get IDEV Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get IDEV Cert: OK\n");
    }

    // GET_IDEV_INFO
    struct caliptra_get_idev_info_resp idev_info_resp;

    status = caliptra_get_idev_info(&idev_info_resp, false);

    if (status) {
        printf("Get IDEV Info: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get IDEV Info: OK\n");
    }

    // POPULATE_IDEV_CERT
    struct caliptra_populate_idev_cert_req populate_idev_req = {};

    status = caliptra_populate_idev_cert(&populate_idev_req, false);

    if (status) {
        printf("Populate IDEV Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Populate IDEV Cert: OK\n");
    }

    // GET_LDEV_CERT
    struct caliptra_get_ldev_cert_resp ldev_cert_resp;

    status = caliptra_get_ldev_cert(&ldev_cert_resp, false);

    if (status) {
        printf("Get LDEV Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get LDEV Cert: OK\n");
    }

    // GET_FMC_ALIAS_CERT
    struct caliptra_get_fmc_alias_cert_resp fmc_alias_cert_resp;

    status = caliptra_get_fmc_alias_cert(&fmc_alias_cert_resp, false);

    if (status) {
        printf("Get FMC Alias Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get FMC Alias Cert: OK\n");
    }

    // GET_RT_ALIAS_CERT
    struct caliptra_get_rt_alias_cert_resp rt_alias_cert_resp;

    status = caliptra_get_rt_alias_cert(&rt_alias_cert_resp, false);

    if (status) {
        printf("Get Runtime Alias Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get Runtime Alias Cert: OK\n");
    }

    // ECDSA384_VERIFY
    struct caliptra_ecdsa_verify_req ecdsa_req = {};

    status = caliptra_ecdsa384_verify(&ecdsa_req, false);

    // Not testing for full success
    // Instead, just want to see it give the right ECC-specific error
    // This still proves the FW recognizes the message and request data and got to the right ECC code
    uint32_t DRIVER_ECC384_KEYGEN_BAD_USAGE = 0x5000f;
    non_fatal_error = caliptra_read_fw_non_fatal_error();
    if (status != MBX_STATUS_FAILED || non_fatal_error != DRIVER_ECC384_KEYGEN_BAD_USAGE) {
        printf("ECDSA384 Verify unexpected result/failure: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("ECDSA384 Verify: OK\n");
    }

    // LMS_VERIFY
    struct caliptra_lms_verify_req lms_req = {};

    status = caliptra_lms_verify(&lms_req, false);

    // Not testing for full success
    // Instead, just want to see it give the right LMS-specific error
    // This still proves the FW recognizes the message and request data and got to the right LMS code
    uint32_t RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM = 0xE0043;
    non_fatal_error = caliptra_read_fw_non_fatal_error();
    if (status != MBX_STATUS_FAILED || non_fatal_error != RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM) {
        printf("LMS Verify unexpected result/failure: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("LMS Verify: OK\n");
    }

    // STASH_MEASUREMENT
    struct caliptra_stash_measurement_req stash_req = {};
    struct caliptra_stash_measurement_resp stash_resp;

    status = caliptra_stash_measurement(&stash_req, &stash_resp, false);

    if (status) {
        printf("Stash Measurement failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Stash Measurement: OK\n");
    }

    // INVOKE_DPE_COMMAND
    // Using GET_PROFILE as an example command
    // TODO: Coverage of other DPE commands should be added
    struct caliptra_invoke_dpe_req dpe_req = {};
    struct caliptra_invoke_dpe_resp dpe_resp;

    dpe_req.data_size = sizeof(struct dpe_get_profile_cmd);
    dpe_req.get_profile_cmd.cmd_hdr.magic = DPE_MAGIC;
    dpe_req.get_profile_cmd.cmd_hdr.cmd_id = DPE_GET_PROFILE;
    dpe_req.get_profile_cmd.cmd_hdr.profile = 0x2;

    status = caliptra_invoke_dpe_command(&dpe_req, &dpe_resp, false);

    if (status) {
        printf("DPE Command failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("DPE Command: OK\n");
    }


    // FW_INFO
    struct caliptra_fw_info_resp fw_info_resp;

    status = caliptra_fw_info(&fw_info_resp, false);

    if (status) {
        printf("FW Info failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FW Info: OK\n");
    }

    // DPE_TAG_TCI
    struct caliptra_dpe_tag_tci_req tag_tci_req = {};

    status = caliptra_dpe_tag_tci(&tag_tci_req, false);

    if (status) {
        printf("DPE Tag TCI failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("DPE Tag TCI: OK\n");
    }

    // DPE_GET_TAGGED_TCI
    struct caliptra_get_tagged_tci_req get_tagged_tci_req = {};
    struct caliptra_get_tagged_tci_resp get_tagged_tci_resp;

    status = caliptra_dpe_get_tagged_tci(&get_tagged_tci_req, &get_tagged_tci_resp, false);

    if (status) {
        printf("DPE Get Tagged TCI failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("DPE Get Tagged TCI: OK\n");
    }

    // Increment PCR Reset Counter
    struct caliptra_increment_pcr_reset_counter_req inc_pcr_rst_cntr_req = {};

    status = caliptra_increment_pcr_reset_counter(&inc_pcr_rst_cntr_req, false);

    if (status) {
        printf("Increment PCR Reset Counter failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Increment PCR Reset Counter: OK\n");
    }

    // Quote PCRs
    struct caliptra_quote_pcrs_req quote_pcrs_req = {};
    struct caliptra_quote_pcrs_resp quote_pcrs_resp;

    status = caliptra_quote_pcrs(&quote_pcrs_req, &quote_pcrs_resp, false);

    if (status) {
        printf("Quote PCRs failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Quote PCRs: OK\n");
    }

    // Extend PCR
    struct caliptra_extend_pcr_req extend_pcr_req = {};
    extend_pcr_req.pcr_idx = 0x4; // First non-reserved index

    status = caliptra_extend_pcr(&extend_pcr_req, false);

    if (status) {
        printf("Extend PCR failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Extend PCR: OK\n");
    }

    // Add subject alt name
    struct caliptra_add_subject_alt_name_req add_subject_alt_name_req = {};
    strcpy((char *)add_subject_alt_name_req.dmtf_device_info, "ChipsAlliance:Caliptra:0123456789");
    add_subject_alt_name_req.dmtf_device_info_size = strlen((char *)add_subject_alt_name_req.dmtf_device_info);

    status = caliptra_add_subject_alt_name(&add_subject_alt_name_req, false);

    if (status) {
        printf("Add Subject Alt Name failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Add Subject Alt Name: OK\n");
    }

    // Certify key extended
    int caliptra_certify_key_extended(struct caliptra_certify_key_extended_req *req, struct caliptra_certify_key_extended_resp *resp, bool async);
    struct caliptra_certify_key_extended_req certify_key_extended_req = {};
    struct caliptra_certify_key_extended_resp certify_key_extended_resp;

    status = caliptra_certify_key_extended(&certify_key_extended_req, &certify_key_extended_resp, false);

    if (status) {
        printf("Certify Key Extended failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Certify Key Extended: OK\n");
    }


    // FIPS_VERSION
    struct caliptra_fips_version_resp version_resp;

    status = caliptra_fips_version(&version_resp, false);

    if (status) {
        printf("FIPS Version failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Version: OK\n");
    }

    // SELF_TEST_START
    status = caliptra_self_test_start(false);

    if (status) {
        printf("FIPS Self Test Start failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Self Test Start: OK\n");
    }

    // Give self test time to run
    for (int i = 0; i < 4000000; i++){
        caliptra_wait();
    }

    // SELF_TEST_GET_RESULTS
    status = caliptra_self_test_get_results(false);

    if (status) {
        printf("FIPS Self Test Get Results failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Self Test Get Results: OK\n");
    }

    // These commands are last since they cause lasting affects on the runtime
    // DISABLE_ATTESTATION
    status = caliptra_disable_attestation(false);

    if (status) {
        printf("Disable Attestation failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Disable Attestation: OK\n");
    }

    // SHUTDOWN
    status = caliptra_shutdown(false);

    if (status) {
        printf("FIPS Shutdown failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FIPS Shutdown: OK\n");
    }

    return failure;
}

int rom_test_devid_csr(const test_info* info)
{
    int failure = 0;

    struct caliptra_buffer caliptra_idevid_csr_buf = {0};
    caliptra_idevid_csr_buf.len = IDEV_CSR_LEN;
    // Allocte a buffer to hold the IDEV CSR using malloc
    caliptra_idevid_csr_buf.data = malloc(caliptra_idevid_csr_buf.len);

    // Check if the buffer was allocated successfully
    if (caliptra_idevid_csr_buf.data == NULL) {
        printf("Failed to allocate memory for IDEV CSR\n");
        return 1;
    }

    bool request_csr = true;
    int status = boot_to_ready_for_fw(info, request_csr);

    if (status){
        dump_caliptra_error_codes();
        failure = 1;
    }

    caliptra_wait_for_csr_ready();


    int ret;
    // Retrieve the IDEV CSR
    if ((ret = caliptra_retrieve_idevid_csr(&caliptra_idevid_csr_buf)) != NO_ERROR) {
        printf("Failed to retrieve IDEV CSR\n");
        printf("Error is 0x%x\n", ret);
        failure = 1;
    } else {
        printf("IDEV CSR retrieved\n");
    }

    // Compare the retrieved IDEV CSR with the expected IDEV CSR
    if (memcmp(caliptra_idevid_csr_buf.data, idev_csr_bytes, caliptra_idevid_csr_buf.len) != 0) {
        printf("IDEV CSR does not match\n");
#ifdef ENABLE_DEBUG
        dump_array_to_file(&caliptra_idevid_csr_buf, "retrieved.bin");
#endif
        failure = 1;
    } else {
        printf("IDEV CSR matches\n");
    }

    caliptra_req_idev_csr_complete();
    caliptra_ready_for_firmware();

    // Test Get Idev CSR now that a CSR is provisioned.
    // GET IDEV CSR
    struct caliptra_get_idev_csr_resp csr_resp = {0};

    status = caliptra_get_idev_csr(&csr_resp, false);

    if (status) {
        printf("Get IDev CSR failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        if (memcmp(csr_resp.data, idev_csr_bytes, csr_resp.data_size) != 0) {
            printf("IDEV CSR does not match\n");
            failure = 1;
        } else {
            printf("Get IDev CSR: OK\n");
        }
    }

    free((void*)caliptra_idevid_csr_buf.data);
    return failure;
}

// Verify signing with an exported cdi
int sign_with_exported_ecdsa_cdi(const test_info* info)
{
    struct dpe_derive_context_exported_cdi_response exported_resp = { 0 };

    int status = boot_to_ready_for_fw(info, false);

    if (status) {
        dump_caliptra_error_codes();
        return 1;
    }

    status = caliptra_upload_fw(&info->image_bundle, false);

    if (status) {
        printf("FW Load Failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        return 1;
    }

    if(derive_context_exported_cdi(&exported_resp, DPE_DERIVE_CONTEXT_FLAG_EXPORT_CDI | DPE_DERIVE_CONTEXT_FLAG_CREATE_CERTIFICATE)) {
        printf("Failed to export CDI\n");
        return 1;
    }

    if (caliptra_verify_ecdsa_signature(&exported_resp)) {
        printf("Sign with exported Ecdsa: OK\n");
    } else {
        printf("Error invalid signature.\n");
        return 1;
    }

    return 0;
}

// Test exported cdi with a new measurement
int sign_with_exported_ecdsa_cdi_hitless(const test_info* info)
{
    struct dpe_derive_context_response derive_resp = { 0 };
    struct dpe_derive_context_exported_cdi_response exported_resp = { 0 };
    struct caliptra_revoke_exported_cdi_handle_req revoke_req = { 0 };

    int status = boot_to_ready_for_fw(info, false);

    if (status){
        dump_caliptra_error_codes();
        return 1;
    }

    status = caliptra_upload_fw(&info->image_bundle, false);

    if (status)
    {
        printf("FW Load Failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        return 1;
    }

    // Create first export cdi and certificate
    if(derive_context_exported_cdi(&exported_resp, DPE_DERIVE_CONTEXT_FLAG_EXPORT_CDI | 
                DPE_DERIVE_CONTEXT_FLAG_CREATE_CERTIFICATE | DPE_DERIVE_CONTEXT_FLAG_RETAIN_PARENT_CONTEXT)) {
        printf("Failed to export first CDI\n");
        return 1;
    }

    if (caliptra_verify_ecdsa_signature(&exported_resp)) {
        printf("Sign with exported Ecdsa: OK\n");
    } else {
        printf("Error invalid signature.\n");
        return 1;
    }

    // Add new measurement.
    if(derive_context(&derive_resp, DPE_DERIVE_CONTEXT_FLAG_RECURSIVE)) {
        printf("Failed to add new measurement.\n");
        return 1;
    }

    // Revoke existing exported CDI 
    memcpy(&revoke_req.exported_cdi_handle, exported_resp.exported_cdi_handle, sizeof(revoke_req.exported_cdi_handle));

    if (caliptra_revoke_exported_cdi_handle(&revoke_req, false)) {
        printf("Error Revoke Exported CDI Handle.\n");
        return 1;
    } else {
        printf("Revoke Exported CDI Handle: OK\n");
    }

    // Create new exported cdi handle and certificate
    if(derive_context_exported_cdi(&exported_resp, DPE_DERIVE_CONTEXT_FLAG_EXPORT_CDI | DPE_DERIVE_CONTEXT_FLAG_CREATE_CERTIFICATE)) {
        printf("Failed to export new CDI\n");
        return 1;
    }

    if (caliptra_verify_ecdsa_signature(&exported_resp)) {
        printf("Sign with exported Ecdsa: OK\n");
    } else {
        printf("Error invalid signature.\n");
        return 1;
    }

    return 0;
}

// Issue FW load commands repeatedly
// Coverage for piecewise FW load and runtime FW updates
int upload_fw_piecewise(const test_info* info)
{
    int failure = 0;
    int status = boot_to_ready_for_fw(info, false);

    if (status){
        printf("Failed to boot to ready for FW: 0x%x\n", status);
        failure = 1;
    }

    // Some "random" size to split up the FW load into chunks
    // These represent the first two chunks, the third chunk is the remainder of the image
    // Sizes of 0 are ignored (meaning one fewer chunk is sent)
    uint32_t chunk_sizes[][2] =    {
                                    {0x4, 0},
                                    {0x1000, 0},
                                    {0x1234, 0},
                                    {0xe924, 0},
                                    {0x8, 0x2000},
                                    {0x2340, 0x4},
                                    {0x388, 0x1844},
                                    };

    // Load FW in a loop, using the offsets above as points to split chunks
    for (int i = 0; i < CALIPTRA_ARRAY_SIZE(chunk_sizes); i++) {
        // Start the FW load
        uint32_t total_fw_size = info->image_bundle.len;
        status = caliptra_upload_fw_start_req(total_fw_size);

        if (status)
        {
            printf("FW Load %d Start Failed: 0x%x\n", i, status);
            dump_caliptra_error_codes();
            failure = 1;
        } else {
            printf("FW Load %d Start: OK\n", i);
        }

        // Ensure other commands report busy during this process
        struct caliptra_fips_version_resp version_resp;
        status = caliptra_fips_version(&version_resp, false);
        if (status != MBX_BUSY) {
            printf("Command during piecewise FW load should report MBX_BUSY. Result was: 0x%x\n", status);
            failure = 1;
        }

        uint32_t sent_bytes = 0;
        uint8_t chunk_count = 0;
        // Upload each of up to 3 chunks
        // The size of the first two chunks comes from the table above
        // The final chunk is the remainder
        // Some chunks may be skipped if their size is 0 in the table
        for (int j = 0; j < 3; j++){
            uint32_t chunk_size;
            if (j == 2) {
                // Final chunk
                chunk_size = total_fw_size - sent_bytes;
            } else {
                chunk_size = chunk_sizes[i][j];
            }

            if (chunk_size != 0){
                // Set up the caliptra_buffer for the chunk and send it
                struct caliptra_buffer fw_chunk = {.data = info->image_bundle.data + sent_bytes, .len = chunk_size};
                status = caliptra_upload_fw_send_data(&fw_chunk);

                if (status)
                {
                    printf("FW Load %d Send Data chunk %d (%d bytes) Failed: 0x%x\n", i, chunk_count, status, chunk_size);
                    dump_caliptra_error_codes();
                    failure = 1;
                } else {
                    printf("FW Load %d Send Data chunk %d (%d bytes): OK\n", i, chunk_count, chunk_size);
                }

                // Track what has been sent
                sent_bytes += chunk_size;
                chunk_count++;
            }
        }

        // Finish the FW load
        status = caliptra_upload_fw_end_req(false);

        if (status)
        {
            printf("FW Load %d End Failed: 0x%x\n", i, status);
            dump_caliptra_error_codes();
            failure = 1;
        } else {
            printf("FW Load %d End: OK\n", i);
        }
    }

    return failure;
}

// Test infrastructure

int global_test_result = 0;

void run_test(int func(const test_info *), const test_info* info, char* test_name)
{
    testbench_reinit();
    int result = func(info);

    if (result) {
        printf("\n\n\t%s FAILED\n", test_name);
        dump_caliptra_error_codes();
        printf("\n\n");
    } else {
        printf("\n\n\t%s PASSED\n\n\n", test_name);
    }

    global_test_result |= result;
}

int run_tests(const test_info* info)
{
    global_test_result = 0;

    hwmod_init(info->rom, info);

    run_test(legacy_boot_test, info, "Legacy boot test");
    run_test(rom_test_all_commands, info, "Test all ROM commands");
    run_test(rt_test_all_commands, info, "Test all Runtime commands");
    run_test(rom_test_devid_csr, info, "Test IDEV CSR GEN");
    run_test(upload_fw_piecewise, info, "Test Piecewise FW Load");
    run_test(sign_with_exported_ecdsa_cdi, info, "Test Sign with Exported ECDSA");
    run_test(sign_with_exported_ecdsa_cdi_hitless, info, "Test Exported CDI Hitless Update");

    if (global_test_result) {
        printf("\t\tlibcaliptra test failures reported\n");
    } else {
        printf("\t\tAll libcaliptra tests passed\n");
    }

    return global_test_result;
}
