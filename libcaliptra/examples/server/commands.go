package main

/*
#cgo CFLAGS: -I./../../inc -g
#cgo LDFLAGS: -L./  -linterface -lcaliptra_hw_model_c_binding -ldl

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <caliptra_api.h>
#include <caliptra_image.h>
#include <caliptra_if.h>

struct caliptra_fuses fuses = {0};
struct caliptra_buffer image_bundle;

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
        fuses.owner_pk_hash[x] = __builtin_bswap32(((uint32_t*)opk_hash)[x]);
    }

    memcpy(&fuses.key_manifest_pk_hash, &vpk_hash, SHA384_DIGEST_BYTE_SIZE);

    if ((status = caliptra_init_fuses(&fuses)) != 0)
    {
        printf("Failed to init fuses: %d\n", status);
    }

    return status;
}
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func Start() {

	romPath := "../out/caliptra_rom.bin"
	os.Setenv("ROM_PATH", romPath)

	fwPath := "../out/image_bundle.bin"
	os.Setenv("FW_PATH", fwPath)

	C.caliptra_bootfsm_go()

	if C.set_fuses() != 0 {
		panic("Failed to set fuses")
	}

	C.caliptra_ready_for_firmware()

	fwPathVar := C.CString(os.Getenv("FW_PATH"))
	defer C.free(unsafe.Pointer(fwPathVar))

	image_bundle := C.read_file_or_exit(fwPathVar)

	C.caliptra_upload_fw(&image_bundle)

	for {
		C.caliptra_wait()
		var version C.struct_caliptra_fips_version
		if C.caliptra_get_fips_version(&version) != 0 {
			panic("Get FIPS Version failed!")
		}
		fmt.Println(version)

		break
	}

	println("Caliptra C API Integration Test Passed!")
}

func Commands(cmd []byte, n int) []byte {
	var req C.struct_caliptra_dpe_req
	var resp C.struct_caliptra_dpe_resp

	// Convert cmd to a byte array
	cCmd := C.CBytes(cmd)
	defer C.free(cCmd)

	// Copy cmd to the req.data field
	fmt.Println(C.size_t(n))
	fmt.Println(C.uint32_t(n))
	C.memcpy(unsafe.Pointer(&req.data[0]), cCmd, C.size_t(n-4))

	req.data_size = C.uint32_t(512)
	fmt.Println(req.data)

	var i int
	for i = 0; i < n-4; i++ {
		fmt.Printf("%02X", req.data[i])
		fmt.Print(" ")
	}

	if C.caliptra_dpe_command(&req, &resp) != 0 {
		panic("Command failed!")
	}

	respPtr := &resp

	// Calculate the offset to the union member based on data_size
	dataSize := int(resp.data_size)
	offset := unsafe.Sizeof(resp.cpl) + unsafe.Sizeof(resp.data_size)
	var selectedBytes []byte

	selectedBytes = C.GoBytes(unsafe.Pointer(uintptr(unsafe.Pointer(respPtr))+offset), C.int(dataSize))

	return selectedBytes
}
