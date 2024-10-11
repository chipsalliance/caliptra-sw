# Licensed under the Apache-2.0 license

if (CONFIG_LIBCALIPTRA)

zephyr_library()

zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/inc)
zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/src)

# This is for caliptra_top_reg.h which has all of the register definitions for Caliptra.
zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/../hw/latest/rtl/src/soc_ifc/rtl)

zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/caliptra_api.c)

endif() # CONFIG_LIBCALIPTRA
