// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#define ECC384_SCALAR_BYTE_SIZE 48
#define ECC384_SCALAR_WORD_SIZE 12
#define SHA384_DIGEST_BYTE_SIZE 48
#define SHA384_DIGEST_WORD_SIZE 12
#define SHA192_DIGEST_BYTE_SIZE 24
#define SHA192_DIGEST_WORD_SIZE 6
#define IMAGE_LMS_OTS_P_PARAM   51
#define IMAGE_LMS_KEY_HEIGHT    15
#define IMAGE_BYTE_SIZE         (128 * 1024)

struct ecc_pub_key {
    uint32_t x[ECC384_SCALAR_WORD_SIZE];
    uint32_t y[ECC384_SCALAR_WORD_SIZE];
};

struct image_ecc_signature {
    uint32_t rcoord[SHA384_DIGEST_WORD_SIZE];
    uint32_t scoord[SHA384_DIGEST_WORD_SIZE];
};

struct lms_pub_key {
    uint32_t lms_algo_type;   // Big Endian
    uint32_t lmots_algo_type; // Big Endian
    uint8_t  id[16];
    uint32_t digest[SHA192_DIGEST_WORD_SIZE];
};

struct lmots_signature {
    uint32_t lmots_algo_type; // Big Endian
    uint32_t nonce[SHA192_DIGEST_WORD_SIZE];
    uint32_t y[SHA192_DIGEST_WORD_SIZE][IMAGE_LMS_OTS_P_PARAM];
};

struct image_lms_signature {
    uint32_t               q;
    struct lmots_signature ots;
    uint32_t               tree_type;
    uint32_t               tree_path[SHA192_DIGEST_WORD_SIZE][IMAGE_LMS_KEY_HEIGHT];
};

struct image_vendor_pubkeys {
    struct ecc_pub_key ecc_pub_keys[4];
    struct lms_pub_key lms_pub_keys[32];
};

struct image_vendor_signatures {
    struct image_ecc_signature ecc_signature;
    struct image_lms_signature lms_signature;
};

struct image_owner_pubkeys {
    struct ecc_pub_key ecc_pub_key;
    struct lms_pub_key lms_pub_key;
};

struct image_owner_signatures {
    struct image_ecc_signature ecc_signature;
    struct image_lms_signature lms_signature;
};

struct caliptra_preamble {
    struct image_vendor_pubkeys    vendor_pub_keys;
    uint32_t                       vendor_ecc_key_index;
    uint32_t                       vendor_lms_key_index;
    struct image_vendor_signatures vendor_sigs;
    struct image_owner_pubkeys     owner_pub_keys;
    struct image_owner_signatures  owner_sigs;
    uint32_t                       reserved[2]; 
};

struct caliptra_header {
    uint32_t header;
    uint64_t revision;
    uint32_t flags;
    uint32_t toc_entry_count;
    uint8_t  toc_digest[48];
};

struct caliptra_toc {
    uint32_t toc_entry_id;
    uint32_t image_type;
    uint8_t  image_revision[20];
    uint64_t image_svn;
    uint64_t image_minimum_svn;
    uint32_t image_load_address;
    uint32_t image_entry_point;
    uint32_t image_offset;
    uint32_t image_size;
    uint8_t  image_hash[48];
};

struct caliptra_image_manifest {
    uint32_t       marker; // "CMAN"
    uint32_t       size;
    struct caliptra_preamble  preamble;
    struct caliptra_header    header;
    struct caliptra_toc       fmc;
    struct caliptra_toc       runtime;
};
