// Licensed under the Apache-2.0 license
use caliptra_image_types::FwVerificationPqcKeyType;

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];
