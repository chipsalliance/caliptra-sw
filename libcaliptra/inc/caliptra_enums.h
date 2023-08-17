// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

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

