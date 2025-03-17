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
#define SHA256_DIGEST_WORD_SIZE 8
#define SHA512_DIGEST_WORD_SIZE 16
#define SHA512_DIGEST_BYTE_SIZE 64
#define IMAGE_LMS_OTS_P_PARAM   51
#define IMAGE_LMS_KEY_HEIGHT    15
#define IMAGE_BYTE_SIZE         (256 * 1024)
#define MLDSA87_PUB_KEY_BYTE_SIZE 2592
#define MLDSA87_PUB_KEY_WORD_SIZE 648
#define MLDSA87_PRIV_KEY_BYTE_SIZE 4896
#define MLDSA87_PRIV_KEY_WORD_SIZE 1224
#define MLDSA87_SIGNATURE_BYTE_SIZE 4628
#define MLDSA87_SIGNATURE_WORD_SIZE 1157
#define PQC_PUB_KEY_BYTE_SIZE MLDSA87_PUB_KEY_BYTE_SIZE
#define PQC_SIGNATURE_BYTE_SIZE MLDSA87_SIGNATURE_BYTE_SIZE

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

struct image_mldsa_pubkey {
    uint32_t key[MLDSA87_PUB_KEY_WORD_SIZE];
};

struct image_pqc_pubkey {
    uint8_t key[PQC_PUB_KEY_BYTE_SIZE];
};

struct image_mldsa_signature {
    uint32_t signature[MLDSA87_SIGNATURE_WORD_SIZE];
};

struct image_pqc_signature {
    uint8_t signature[PQC_SIGNATURE_BYTE_SIZE];
};

struct image_ecc_key_descriptor {
    uint16_t version;
    uint8_t reserved;
    uint8_t key_hash_count;
    uint32_t key_hash[4][SHA384_DIGEST_WORD_SIZE];
};

struct image_pqc_key_descriptor {
    uint16_t version;
    uint8_t key_type;
    uint8_t key_hash_count;
    uint32_t key_hash[32][SHA384_DIGEST_WORD_SIZE];
};

struct image_vendor_pub_key_info {
    struct image_ecc_key_descriptor ecc_key_descriptor;
    struct image_pqc_key_descriptor pqc_key_descriptor;
};

struct image_vendor_pubkeys {
    struct ecc_pub_key ecc_pub_keys[4];
    struct lms_pub_key lms_pub_keys[32];
    struct image_mldsa_pubkey mldsa_pub_keys[4];
};

struct image_signatures {
    struct image_ecc_signature ecc_sig;
    struct image_pqc_signature pqc_sig;
};

struct vendor_signed_data {
    uint8_t vendor_not_before[15];
    uint8_t vendor_not_after[15];
    uint8_t reserved[10];
};

struct owner_signed_data {
    uint8_t owner_not_before[15];
    uint8_t owner_not_after[15];
    uint8_t reserved[10];
};

struct image_owner_pubkeys {
    struct ecc_pub_key ecc_pub_key;
    struct image_pqc_pubkey pqc_pub_key;
};

struct caliptra_preamble {
    struct image_vendor_pub_key_info vendor_pub_key_info;
    uint32_t                       vendor_ecc_pub_key_idx;
    struct ecc_pub_key             vendor_ecc_active_pub_key;
    uint32_t                       vendor_pqc_pub_key_idx;
    struct image_pqc_pubkey        vendor_pqc_active_pub_key;
    struct image_signatures        vendor_sigs;
    struct image_owner_pubkeys     owner_pub_keys;
    struct image_signatures        owner_sigs;
    uint32_t                       _rsvd[2];
};

struct caliptra_header {
    uint32_t revision[2];
    uint32_t vendor_ecc_pub_key_idx;
    uint32_t vendor_pqc_pub_key_idx;
    uint32_t flags;
    uint32_t toc_len;
    uint32_t pl0_pauser;
    uint32_t toc_digest[SHA384_DIGEST_WORD_SIZE];
    uint32_t svn;
    struct vendor_signed_data vendor_data;
    struct owner_signed_data owner_data;
};

struct caliptra_toc {
    uint32_t id;
    uint32_t toc_type;
    uint8_t  revision[20];
    uint32_t version;
    uint32_t reserved[2];
    uint32_t load_addr;
    uint32_t entry_point;
    uint32_t offset;
    uint32_t size;
    uint32_t digest[SHA384_DIGEST_WORD_SIZE];
};

struct caliptra_image_manifest {
    uint32_t       marker; // "CMAN"
    uint32_t       size;
    uint8_t        pqc_key_type;
    uint8_t        reserved[3];
    struct caliptra_preamble  preamble;
    struct caliptra_header    header;
    struct caliptra_toc       fmc;
    struct caliptra_toc       runtime;
};
