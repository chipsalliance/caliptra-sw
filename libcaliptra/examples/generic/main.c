// Licensed under the Apache-2.0 license
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "caliptra_api.h"
#include "caliptra_image.h"

// Arbitrary example only - values must be customized/tuned for the SoC
static const uint64_t wdt_timeout = 0xA0000000;         // approximately 5s for 500MHz clock
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint16_t itrng_entropy_low_threshold = 0x1;
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint16_t itrng_entropy_high_threshold = 0xFFFF;
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint16_t itrng_entropy_repetition_count = 0xFFFF;
// Arbitrary example only - values must be customized/tuned for the SoC
static const uint32_t apb_pauser = 0x1;

// Exists for testbench only - not part of interface for actual implementation
extern void testbench_reinit(void);

struct caliptra_buffer image_bundle;
struct caliptra_fuses fuses = {0};

__attribute__((section("VPK_HASH"))) uint8_t vpk_hash[48];
__attribute__((section("OPK_HASH"))) uint8_t opk_hash[48];

static const uint32_t default_uds_seed[] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
                                             0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
                                             0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f };

static const uint32_t default_field_entropy[] = { 0x80818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f,
                                                  0x90919293, 0x94959697, 0x98999a9b, 0x9c9d9e9f };

static int set_fuses()
{
    int status;

    fuses = (struct caliptra_fuses){0};

    memcpy(&fuses.uds_seed, &default_uds_seed, sizeof(default_uds_seed));
    memcpy(&fuses.field_entropy, &default_field_entropy, sizeof(default_field_entropy));

    for (int x = 0; x < SHA384_DIGEST_WORD_SIZE; x++)
    {
        // Pub key hash fuses are stored as big-endian
        fuses.owner_pk_hash[x] = __builtin_bswap32(((uint32_t*)opk_hash)[x]);
        fuses.key_manifest_pk_hash[x] = __builtin_bswap32(((uint32_t*)vpk_hash)[x]);
    }

    if ((status = caliptra_init_fuses(&fuses)) != 0)
    {
        printf("Failed to init fuses: %d\n", status);
    }

    return status;
}

void dump_caliptra_error_codes()
{
    printf("Caliptra FW error non-fatal code is 0x%x\n", caliptra_read_fw_non_fatal_error());
    printf("Caliptra FW error fatal code is 0x%x\n", caliptra_read_fw_fatal_error());
}

int boot_to_ready_for_fw()
{
    int status;

    // Initialize FSM GO
    caliptra_bootfsm_go();

    caliptra_set_wdt_timeout(wdt_timeout);

    caliptra_configure_itrng_entropy(itrng_entropy_low_threshold,
                                     itrng_entropy_high_threshold,
                                     itrng_entropy_repetition_count);

    // Set up our PAUSER value for the mailbox regs
    status = caliptra_mbox_pauser_set_and_lock(apb_pauser);
    if (status) {
        printf("Set MBOX pauser Failed: 0x%x\n", status);
        return status;
    }

    // Set up our PAUSER value for the fuse regs
    status = caliptra_fuse_pauser_set_and_lock(apb_pauser);
    if (status) {
        printf("Set FUSE pauser Failed: 0x%x\n", status);
        return status;
    }

    set_fuses();

    // Wait until ready for FW
    caliptra_ready_for_firmware();

    return status;
}

int legacy_boot_test()
{
    int failure = 0;
    int status = boot_to_ready_for_fw();

    if (status){
        failure = 1;
    }

    // Load Image Bundle
    // FW_PATH is defined on the compiler command line
    status = caliptra_upload_fw(&image_bundle, false);

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
int rom_test_all_commands()
{
    int failure = 0;
    int status = boot_to_ready_for_fw();

    if (status){
        dump_caliptra_error_codes();
        failure = 1;
    }

    // STASH_MEASUREMENT
    struct caliptra_stash_measurement_req stash_req = {};
    struct caliptra_stash_measurement_resp stash_resp = {};

    status = caliptra_stash_measurement(&stash_req, &stash_resp, false);

    if (status) {
        printf("Stash Measurement failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Stash Measurement: OK\n");
    }

    // CAPABILITIES
    struct caliptra_capabilities_resp cap_resp = {};

    status = caliptra_capabilities(&cap_resp, false);

    if (status) {
        printf("Capabilities failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Capabilities: OK\n");
    }

    // FIPS_VERSION
    struct caliptra_fips_version_resp version_resp = {};

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
int rt_test_all_commands()
{
    int failure = 0;
    uint32_t non_fatal_error;
    int status = boot_to_ready_for_fw();

    if (status){
        failure = 1;
    }

    // Load Image Bundle
    // FW_PATH is defined on the compiler command line
    status = caliptra_upload_fw(&image_bundle, false);

    if (status)
    {
        printf("FW Load Failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("FW Load: OK\n");
    }

    // GET_IDEV_CERT
    struct caliptra_get_idev_cert_req idev_cert_req = {};
    struct caliptra_get_idev_cert_resp idev_cert_resp = {};

    status = caliptra_get_idev_cert(&idev_cert_req, &idev_cert_resp, false);

    if (status) {
        printf("Get IDEV Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get IDEV Cert: OK\n");
    }

    // GET_IDEV_INFO
    struct caliptra_get_idev_info_resp idev_info_resp = {};

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
    struct caliptra_get_ldev_cert_resp ldev_cert_resp = {};

    status = caliptra_get_ldev_cert(&ldev_cert_resp, false);

    if (status) {
        printf("Get LDEV Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get LDEV Cert: OK\n");
    }

    // GET_FMC_ALIAS_CERT
    struct caliptra_get_fmc_alias_cert_resp fmc_alias_cert_resp = {};

    status = caliptra_get_fmc_alias_cert(&fmc_alias_cert_resp, false);

    if (status) {
        printf("Get FMC Alias Cert failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Get FMC Alias Cert: OK\n");
    }

    // GET_RT_ALIAS_CERT
    struct caliptra_get_rt_alias_cert_resp rt_alias_cert_resp = {};

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
    struct caliptra_stash_measurement_resp stash_resp = {};

    status = caliptra_stash_measurement(&stash_req, &stash_resp, false);

    if (status) {
        printf("Stash Measurement failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Stash Measurement: OK\n");
    }

    // INVOKE_DPE_COMMAND
    struct caliptra_invoke_dpe_req dpe_req = {};
    struct caliptra_invoke_dpe_resp dpe_resp = {};

    status = caliptra_invoke_dpe_command(&dpe_req, &dpe_resp, false);

    // Not testing for full success
    // Instead, just want to see it give the right DPE-specific error
    // This still proves the FW recognizes the message and request data and got to the right DPE code
    uint32_t RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED = 0xe0027;
    non_fatal_error = caliptra_read_fw_non_fatal_error();
    if (status != MBX_STATUS_FAILED || non_fatal_error != RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED) {
        printf("DPE Command unexpected result/failure: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("DPE Command: OK\n");
    }


    // FW_INFO
    struct caliptra_fw_info_resp fw_info_resp = {};

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
    struct caliptra_get_tagged_tci_resp get_tagged_tci_resp = {};

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
    struct caliptra_quote_pcrs_resp quote_pcrs_resp = {};

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
    struct caliptra_certify_key_extended_resp certify_key_extended_resp = {};

    status = caliptra_certify_key_extended(&certify_key_extended_req, &certify_key_extended_resp, false);

    if (status) {
        printf("Certify Key Extended failed: 0x%x\n", status);
        dump_caliptra_error_codes();
        failure = 1;
    } else {
        printf("Certify Key Extended: OK\n");
    }


    // FIPS_VERSION
    struct caliptra_fips_version_resp version_resp = {};

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


// Test infrastructure

int global_test_result = 0;

void run_test( int func(void), char* test_name)
{
    testbench_reinit();
    int result = func();

    if (result) {
        printf("\n\n\t%s FAILED\n", test_name);
        dump_caliptra_error_codes();
        printf("\n\n");
    } else {
        printf("\n\n\t%s PASSED\n\n\n", test_name);
    }

    global_test_result |= result;
}

int main(int argc, char *argv[])
{
    global_test_result = 0;

    run_test(legacy_boot_test, "Legacy boot test");
    run_test(rom_test_all_commands, "Test all ROM commands");
    run_test(rt_test_all_commands, "Test all Runtime commmands");

    if (global_test_result) {
        printf("\t\tlibcaliptra test failures reported\n");
    } else {
        printf("\t\tAll libcaliptra tests passed\n");
    }

    return global_test_result;
}
