// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * libcaliptra_error
 *
 * Error codes for all possible lib caliptra failures
 */
enum libcaliptra_error {
    NO_ERROR = 0,
    // General
    INVALID_PARAMS              = 0x100,
    API_INTERNAL_ERROR          = 0x101,
    REG_ACCESS_ERROR            = 0x102,
    PAUSER_LOCKED               = 0x103,
    // Fuse
    NOT_READY_FOR_FUSES         = 0x200,
    STILL_READY_FOR_FUSES       = 0x201,
    // Mailbox
    MBX_BUSY                    = 0x300,
    MBX_NO_MSG_PENDING          = 0x301,
    MBX_COMPLETE_NOT_READY      = 0x302,
    MBX_STATUS_FAILED           = 0x303,
    MBX_STATUS_UNKNOWN          = 0x304,
    MBX_STATUS_NOT_IDLE         = 0x305,
    MBX_RESP_NO_HEADER          = 0x306,
    MBX_RESP_CHKSUM_INVALID     = 0x307,
    MBX_RESP_FIPS_NOT_APPROVED  = 0x308,

    // MFG
    IDEV_CSR_NOT_READY = 0x400,
};

/**
 * device_lifecycle
 *
 * Device life cycle states
 */
enum device_lifecycle {
    Unprovisioned = 0,
    Manufacturing = 1,
    Reserved2 = 2,
    Production = 3,
};

/**
 * fips_status
 *
 * All valid FIPS status codes.
 */
enum fips_status {
    FIPS_STATUS_APPROVED = 0,
};

enum toc_entry_id {
    FMC     = 0x00000001,
    Runtime = 0x00000002,
    MAX     = 0xFFFFFFFF,
};

// The below enums are placeholders to set up the baseline
// required for communication of DPE commands to Caliptra
// firmware.

enum dpe_commands {
    DPE_GET_PROFILE        = 0x1,
    DPE_INITIALIZE_CONTEXT = 0x7,
    DPE_DERIVE_CHILD       = 0x8,
    DPE_CERTIFY_KEY        = 0x9,
    DPE_SIGN               = 0xA,
    DPE_ROTATE_CTX_HANDLE  = 0xE,
    DPE_DESTROY_CTX        = 0xF,
    DPE_GET_CERT_CHAIN     = 0x80,
    DPE_EXTEND_TCI         = 0x81,
    DPE_TAG_TCI            = 0x82,
    DPE_GET_TAGGED_TCI     = 0x83,
};

enum dpe_error_codes {
    DPE_NO_ERROR               = 0,
    DPE_INTERNAL_ERROR         = 1,
    DPE_INVALID_COMMAND        = 2,
    DPE_INVALID_ARGUMENT       = 3,
    DPE_ARGUMENT_NOT_SUPPORTED = 4,
    DPE_INVALID_HANDLE         = 0x1000,
    DPE_INVALID_LOCALITY       = 0x1001,
    DPE_BADTAG                 = 0x1002,
    DPE_MAXTCIS                = 0x1003,
    DPE_PLATFORM_ERROR         = 0x1004,
    DPE_CRYPTO_ERROR           = 0x1005,
    DPE_HASH_ERROR             = 0x1006,
    DPE_RAND_ERROR             = 0x1007,
};

#define DPE_PROFILE_256 1
#define DPE_PROFILE_384 2

enum dpe_profile {
    P256Sha256 = DPE_PROFILE_256,
    P384Sha384 = DPE_PROFILE_384,
};
