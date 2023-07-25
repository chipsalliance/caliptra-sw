// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>

typedef uint32_t caliptra_checksum;

struct ecdsa384_sigverify {
    caliptra_checksum checksum;
    uint8_t           pub_key_x[48];
    uint8_t           pub_key_y[48];
    uint8_t           signature_r[48];
    uint8_t           signature_s[48];
};

struct stash_measurement_req {
    caliptra_checksum checksum;
    uint8_t           metadata[4];
    uint8_t           measurement[48];
};

struct stash_mesurement_resp {
    caliptra_checksum checksum;
    uint32_t          dpe_result;
};

struct dpe {
    caliptra_checksum checksum;
    uint8_t           data_start;
};

struct dpe_result {
    caliptra_checksum checksum;
    uint32_t           result;
};

struct caliptra_fips_version {
    uint32_t mode;
    uint32_t fips_rev[3];
    uint8_t name[12];
};
/**
 * caliptra_buffer
 *
 * Transfer buffer for Caliptra mailbox commands
 */
#if !defined(HWMODEL)
struct caliptra_buffer {
  const uint8_t *data; //< Pointer to a buffer with data to send/space to receive
  uintptr_t len;       //< Size of the buffer
};
#endif
