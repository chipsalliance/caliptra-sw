FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"

SRC_URI:append = " file://bsp.cfg"
KERNEL_FEATURES:append = " bsp.cfg"
SRC_URI += "file://user_2025-05-30-13-46-00.cfg \
            file://user_2025-05-30-15-49-00.cfg \
            file://user_2025-05-30-17-59-00.cfg \
            file://user_2025-05-30-19-13-00.cfg \
            file://user_2025-05-30-20-15-00.cfg \
            file://user_2025-06-03-00-24-00.cfg \
            file://user_2025-06-03-16-54-00.cfg \
            file://user_2025-07-11-17-09-00.cfg \
            file://user_2025-07-11-19-35-00.cfg \
            file://user_2025-07-11-20-39-00.cfg \
            file://user_2025-08-26-00-39-00.cfg \
            "

