package main

// #cgo CFLAGS: -I./../out/debug -std=c99
// #cgo LDFLAGS: -L./../out/debug -lcaliptra_hw_model_c_binding -lc_wrapper -ldl
// #include "../../../../hw-latest/caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg.h"
// #include "caliptra_api.h"
// #include "caliptra_fuses.h"
// #include "caliptra_mbox.h"
// #include "c_wrapper.h"
// #include <stdlib.h>
// #include <stdio.h>
// #include <stdint.h>
// #include <string.h>
// #include <errno.h>
// #include <unistd.h>

import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// Initialize Model
var model *C.caliptra_model

func read_file_or_die(path *C.char) C.caliptra_buffer {
	// Open File in Read Only Mode
	fp := C.fopen(path, C.CString("r"))
	if fp == nil {
		fmt.Printf("Cannot find file %s \n", path)
		os.Exit(int(C.ENOENT))
	}

	var buffer C.caliptra_buffer

	// Get File Size
	C.fseek(fp, 0, C.SEEK_END)
	buffer.len = C.ulong(C.ftell(fp))
	C.fseek(fp, 0, C.SEEK_SET)

	// Allocate Buffer Memory
	buffer.data = (*C.uchar)(C.malloc(C.size_t(buffer.len)))
	if buffer.data == nil {
		fmt.Println("Cannot allocate memory for buffer->data \n")
		os.Exit(int(C.ENOMEM))
	}

	// Read Data in Buffer
	C.fread(unsafe.Pointer(buffer.data), C.size_t(buffer.len), 1, fp)

	return buffer
}

func Start() {

	romPath := "../out/caliptra_rom.bin"
	fwPath := "../out/image_bundle.bin"

	// Initialize Params
	initParams := C.caliptra_model_init_params{
		rom:  read_file_or_die(C.CString(romPath)),
		dccm: C.caliptra_buffer{data: nil, len: 0},
		iccm: C.caliptra_buffer{data: nil, len: 0},
	}

	C.caliptra_model_init_default(initParams, &model)

	var fuses C.caliptra_fuses
	C.caliptra_init_fuses(model, &fuses)

	// Initialize FSM GO
	C.caliptra_bootfsm_go(model)
	C.caliptra_model_step(model)

	// Step until ready for FW
	for C.caliptra_model_ready_for_fw(model) {
		C.caliptra_model_step(model)
	}

	// Load Image Bundle
	imageBundle := read_file_or_die(C.CString(fwPath))
	C.caliptra_upload_fw(model, &imageBundle)

	// Run Until RT is ready to receive commands
	for {
		C.caliptra_model_step(model)
		buffer := C.caliptra_model_output_peek(model)
		if C.strstr((*C.char)(unsafe.Pointer(buffer.data)), C.CString("Caliptra RT listening for mailbox commands...")) != nil {
			break
		}
	}
	fmt.Println("Caliptra C Smoke Test Passed \n")
}

func Commands(bytes []byte) []byte {
	var test C.uint32_t

	cBytes := (*C.uint8_t)(unsafe.Pointer(&bytes[0])) // Pointer to the first element
	length := C.size_t(len(bytes))

	dataSize := C.uint32_t(length)
	profileBuffer := C.create_invoke_dpe_command(cBytes, dataSize)

	var Check C.caliptra_output
	var profile C.int
	profile = C.caliptra_get_profile(model, &profileBuffer, test, &Check)

	dataSlice := C.GoBytes(unsafe.Pointer(&Check.data[0]), C.int(Check.data_size))

	return dataSlice
}
