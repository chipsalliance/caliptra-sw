// Licensed under the Apache-2.0 license

package dpe

/*
#cgo CFLAGS: -I../../libcaliptra/inc -I../../hw-model/c-binding/out -g
#cgo LDFLAGS: -L../../target/debug -L../../libcaliptra  -lcaliptra -lcaliptra_hw_model_c_binding -ldl -lrt
#define HWMODEL
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "caliptra_model.h"
#include <caliptra_api.h>
#include <caliptra_image.h>
#include <caliptra_if.h>

__attribute__((weak)) struct caliptra_fuses fuses = {0};
__attribute__((weak)) __attribute__((section("VPK_HASH"))) uint8_t vpk_hash[48];
__attribute__((weak)) __attribute__((section("OPK_HASH"))) uint8_t opk_hash[48];
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
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"unsafe"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
)

type CptraModel struct {
	currentLocality uint32
	client.Transport
}

// The libcaliptra API requires this to be global since the register read/write
// APIs need to be callable from C
var CALIPTRA_C_MODEL *C.struct_caliptra_model

//export caliptra_write_u32
func caliptra_write_u32(address C.uint32_t, data C.uint32_t) C.int {
	result := C.caliptra_model_apb_write_u32(CALIPTRA_C_MODEL, address, data)

	C.caliptra_model_step(CALIPTRA_C_MODEL)

	return result
}

//export caliptra_read_u32
func caliptra_read_u32(address C.uint32_t, data *C.uint32_t) C.int {
	return C.caliptra_model_apb_read_u32(CALIPTRA_C_MODEL, address, data)
}

//export caliptra_wait
func caliptra_wait() {
	C.caliptra_model_step(CALIPTRA_C_MODEL)
}

// Emulator can be started and stopped.
func (s *CptraModel) HasPowerControl() bool {
	return true
}

func getHWModel() *C.struct_caliptra_model {
	if CALIPTRA_C_MODEL != nil {
		return CALIPTRA_C_MODEL
	}

	romPath := os.Getenv("ROM_PATH")
	var params C.struct_caliptra_model_init_params

	rom, err := ioutil.ReadFile(romPath)
	if err != nil {
		log.Fatal(err)
	}

	cRom := C.CBytes(rom)
	defer C.free(cRom)

	params.rom.data = (*C.uchar)(cRom)
	params.rom.len = C.uintptr_t(len(rom))

	status := C.caliptra_model_init_default(params, &CALIPTRA_C_MODEL)
	if status != 0 {
		panic("Failed to initialize caliptra model")
	}

	return CALIPTRA_C_MODEL
}

// Start the Emulator.
func (s *CptraModel) PowerOn() error {
	model := getHWModel()
	if model == nil {
		panic("Failed to get HW model")
	}

	C.caliptra_bootfsm_go()

	if C.set_fuses() != 0 {
		panic("Failed to set fuses")
	}

	C.caliptra_ready_for_firmware()

	bundlePath := os.Getenv("FW_PATH")
	fwBundle, err := ioutil.ReadFile(bundlePath)
	if err != nil {
		log.Fatal(err)
	}

	var bundleBuf C.struct_caliptra_buffer

	cBundle := C.CBytes(fwBundle)
	defer C.free(cBundle)

	bundleBuf.data = (*C.uchar)(cBundle)
	bundleBuf.len = C.uintptr_t(len(fwBundle))
	C.caliptra_upload_fw(&bundleBuf, false)

	return nil
}

// Kill the emulator in a way that it can cleanup before closing.
func (s *CptraModel) PowerOff() error {
	C.caliptra_model_destroy(CALIPTRA_C_MODEL)
	CALIPTRA_C_MODEL = nil

	return nil
}

func (s *CptraModel) SendCmd(buf []byte) ([]byte, error) {
	var req C.struct_caliptra_invoke_dpe_req
	var resp C.struct_caliptra_invoke_dpe_resp

	// Caliptra expects all DPE commands to fill the whole data buffer
	C.memcpy(unsafe.Pointer(&req.data), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	req.data_size = C.uint32_t(512)

	cptraStatus := C.caliptra_invoke_dpe_command(&req, &resp, false)
	if cptraStatus != 0 {
		return []byte{}, fmt.Errorf("Failed to send DPE command, error 0x%08x", int(cptraStatus))
	}

	mboxStatus := C.caliptra_read_fw_non_fatal_error()
	if mboxStatus != 0 {
		return []byte{}, fmt.Errorf("Caliptra mailbox returned error 0x%08x", int(mboxStatus))
	}

	respPtr := &resp

	// Calculate the offset to the union member based on data_size
	offset := unsafe.Sizeof(resp.cpl) + unsafe.Sizeof(resp.data_size)
	var selectedBytes []byte

	selectedBytes = C.GoBytes(unsafe.Pointer(uintptr(unsafe.Pointer(respPtr))+offset), (C.int)(resp.data_size))

	return selectedBytes, nil
}

func (s *CptraModel) GetSupport() *client.Support {
	// Expected support vector
	return &client.Support{
		Simulation:          true,
		Recursive:           true,
		AutoInit:            true,
		RotateContext:       true,
		X509:                true,
		Csr:                 true,
		IsSymmetric:         true,
		InternalInfo:        true,
		InternalDice:        true,
		IsCA:                true,
		RetainParentContext: true,
	}
}

func (s *CptraModel) GetSupportedLocalities() []uint32 {
	// TODO: Make this configurable, since it will be SoC specific
	return []uint32{0, 1}
}

func (s *CptraModel) HasLocalityControl() bool {
	// TODO: Hook this up to HwModel
	return false
}

func (s *CptraModel) SetLocality(locality uint32) {
	// TODO: Hook this up to HwModel
	s.currentLocality = locality
}

func (s *CptraModel) GetLocality() uint32 {
	return s.currentLocality
}

func (s *CptraModel) GetMaxTciNodes() uint32 {
	return 24
}

func (s *CptraModel) GetProfileMajorVersion() uint16 {
	return 0
}

func (s *CptraModel) GetProfileMinorVersion() uint16 {
	return 10
}

func (s *CptraModel) GetProfileVendorID() uint32 {
	return binary.BigEndian.Uint32([]byte{'C', 'T', 'R', 'A'})
}

func (s *CptraModel) GetProfileVendorSku() uint32 {
	return binary.BigEndian.Uint32([]byte{'C', 'T', 'R', 'A'})
}

func (s *CptraModel) GetIsInitialized() bool {
	// Always auto initialized
	return true
}

func (s *CptraModel) SetIsInitialized(isInitialized bool) {
	// no-op. Always initialized
}
