// Licensed under the Apache-2.0 license

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CALIPTRA_MODEL_STATUS_OK 0

typedef struct caliptra_buffer {
  const uint8_t *data;
  uintptr_t len;
} caliptra_buffer;

enum DeviceLifecycle {
    Unprovisioned = 0,
    Manufacturing = 1,
    Reserved2 = 2,
    Production = 3,
};

typedef struct caliptra_fuses {
    uint32_t uds_seed[12];
    uint32_t field_entropy[8];
    uint32_t key_manifest_pk_hash[12];
    uint32_t key_manifest_pk_hash_mask : 4;
    uint32_t rsvd : 28;
    uint32_t owner_pk_hash[12];
    uint32_t fmc_key_manifest_svn;
    uint32_t runtime_svn[4];
    bool anti_rollback_disable;
    uint32_t idevid_cert_attr[24];
    uint32_t idevid_manuf_hsm_id[4];
    enum DeviceLifecycle life_cycle;
} caliptra_fuses;

typedef struct caliptra_model_init_params {
  struct caliptra_buffer rom;
  struct caliptra_buffer dccm;
  struct caliptra_buffer iccm;
} caliptra_model_init_params;

typedef struct caliptra_model {
  uint8_t _unused[0];
} caliptra_model;

struct person {
  char *name;
  int age;
};

typedef uint32_t caliptra_checksum;

enum fips_status {
    FIPS_STATUS_APPROVED = 0,
};

struct caliptra_completion {
    uint32_t checksum;
    enum fips_status fips;
};

struct caliptra_fips_version {
    struct caliptra_completion cpl;
    uint32_t mode;
    uint32_t fips_rev[3];
    uint8_t name[12];
};

typedef struct caliptra_output {
    caliptra_checksum chksum;
    enum fips_status fips;
    uint32_t data_size;
    uint8_t data[]; // Flexible array member, size depends on usage
}caliptra_output;

int greet(struct person *p);

/**
 * # Safety
 */
int caliptra_model_init_default(struct caliptra_model_init_params params,
                                struct caliptra_model **model);

/**
 * # Safety
 */
void caliptra_model_destroy(struct caliptra_model *model);

/**
 * # Safety
 */
int caliptra_model_apb_read_u32(struct caliptra_model *model,
                                unsigned int addr,
                                unsigned int *data);

/**
 * # Safety
 */
int caliptra_model_apb_write_u32(struct caliptra_model *model,
                                 unsigned int addr,
                                 unsigned int data);

/**
 * # Safety
 */
bool caliptra_model_ready_for_fuses(struct caliptra_model *model);

/**
 * # Safety
 */
bool caliptra_model_ready_for_fw(struct caliptra_model *model);

/**
 * # Safety
 */
int caliptra_model_step(struct caliptra_model *model);

/**
 * # Safety
 */
bool caliptra_model_exit_requested(struct caliptra_model *model);

/**
 * # Safety
 */
struct caliptra_buffer caliptra_model_output_peek(struct caliptra_model *model);
