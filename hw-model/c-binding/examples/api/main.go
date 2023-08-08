package main

// #cgo CFLAGS: -I./../out/debug
// #cgo LDFLAGS: -L./../out/debug -lcaliptra_hw_model_c_binding -ldl
// #include "../caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg.h"
// #include "caliptra_api.h"
// #include "caliptra_fuses.h"
// #include "caliptra_mbox.h"
import "C"

import (
	"fmt"
	"unsafe"
	"encoding/binary"
)

// Define the Go struct for caliptra_buffer
type caliptraBuffer struct {
	data []byte
	len  uint32
}

// Define the Go struct for caliptra_model
type caliptraModel struct {
	// Add the necessary fields of caliptra_model if required
}

func main() {
	// Create a dummy caliptraModel instance (replace this with the actual implementation)
	model := &caliptraModel{}

	// Create a dummy buffer for firmware data (replace this with the actual data)
	fwData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	fwBuffer := &caliptraBuffer{
		data: fwData,
		len:  uint32(len(fwData)),
	}

	// Initialize fuses
	if err := caliptraInitFuses(model, fwBuffer); err != 0 {
		fmt.Printf("Error initializing fuses: %d\n", err)
		return
	}

	// Start the boot FSM
	if err := caliptraBootFsmGo(model); err != 0 {
		fmt.Printf("Error starting boot FSM: %d\n", err)
		return
	}

	// Execute the mailbox command
	if err := mailboxExecute(model, 0x12345678, fwBuffer, nil); err != 0 {
		fmt.Printf("Error executing mailbox command: %d\n", err)
		return
	}

	fmt.Println("Mailbox command executed successfully!")
}

// Helper function to copy Go []byte to C array
func copySliceToCArray(dest *[12]C.uint32_t, src []byte, size int) {
	if len(src) != size*4 {
		panic("Invalid source slice length")
	}
	for i := 0; i < size; i++ {
		dest[i] = C.uint32_t(binary.LittleEndian.Uint32(src[i*4:]))
	}
}

// Implement the Go wrapper functions for the C functions
func caliptraInitFuses(model *caliptraModel, fuses *caliptraBuffer) int {
	// Convert Go structs to C structs
	cModel := (*C.struct_caliptra_model)(unsafe.Pointer(model))

	// Call the C function
	cFuses := C.struct_caliptra_fuses{}
	/*copySliceToCArray(&cFuses.uds_seed, fuses.data, 12)
	copySliceToCArray(&cFuses.field_entropy, fuses.data[48:], 8)
	copySliceToCArray(&cFuses.key_manifest_pk_hash, fuses.data[80:], 12)
	copySliceToCArray(&cFuses.owner_pk_hash, fuses.data[112:], 12)
	cFuses.fmc_key_manifest_svn = C.uint32_t(binary.LittleEndian.Uint32(fuses.data[148:]))
	copySliceToCArray(&cFuses.runtime_svn, fuses.data[152:], 4)
	cFuses.anti_rollback_disable = C._Bool(binary.LittleEndian.Uint32(fuses.data[184:]) != 0)
	copySliceToCArray(&cFuses.idevid_cert_attr, fuses.data[188:], 24)
	copySliceToCArray(&cFuses.idevid_manuf_hsm_id, fuses.data[376:], 4)
	cFuses.life_cycle = C.enum_DeviceLifecycle(binary.LittleEndian.Uint32(fuses.data[392:])) */

	ret := C.caliptra_init_fuses(cModel, &cFuses)

	return int(ret)
}


func caliptraBootFsmGo(model *caliptraModel) int {
	// Convert Go structs to C structs
	cModel := (*C.struct_caliptra_model)(unsafe.Pointer(model))

	// Call the C function
	ret := C.caliptra_bootfsm_go(cModel)

	return int(ret)
}

func caliptraMailboxExecute(model *caliptraModel, cmd uint32, mboxTxBuffer *caliptraBuffer, mboxRxBuffer *caliptraBuffer) int {
	// Convert Go structs to C structs
	cModel := (*C.struct_caliptra_model)(unsafe.Pointer(model))
	cMboxTxBuffer := (*C.struct_caliptra_buffer)(unsafe.Pointer(mboxTxBuffer))
	var cMboxRxBuffer *C.struct_caliptra_buffer

	if mboxRxBuffer != nil {
		cMboxRxBuffer = (*C.struct_caliptra_buffer)(unsafe.Pointer(mboxRxBuffer))
	}

	// Call the C function
	ret := C.caliptra_mailbox_execute(cModel, C.uint32_t(cmd), cMboxTxBuffer, cMboxRxBuffer)

	return int(ret)
}

func caliptraUploadFw(model *caliptraModel, fwBuffer *caliptraBuffer) int {
	// Convert Go structs to C structs
	cModel := (*C.struct_caliptra_model)(unsafe.Pointer(model))
	cFwBuffer := (*C.struct_caliptra_buffer)(unsafe.Pointer(fwBuffer))

	// Call the C function
	ret := C.caliptra_upload_fw(cModel, cFwBuffer)

	return int(ret)
}

// Implement the Go wrapper function for the mailbox_execute C function
func mailboxExecute(model *caliptraModel, cmd uint32, mboxTxBuffer *caliptraBuffer, mboxRxBuffer *caliptraBuffer) int {
	// Call the caliptraMailboxExecute wrapper function with the provided arguments
	return caliptraMailboxExecute(model, cmd, mboxTxBuffer, mboxRxBuffer)
}
