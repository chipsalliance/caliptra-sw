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
)

// Define the Go struct for caliptra_buffer
type caliptraBuffer struct {
	data *C.uint8_t
	len  C.uintptr_t
}

// Define the Go struct for caliptra_model
type caliptraModel struct {
	_unused [0]byte
}

func main() {
	// Initialize caliptraModel
	var model *C.struct_caliptra_model

	// Create a dummy buffer for firmware data (replace this with the actual data)
	fwData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	fwBuffer := &caliptraBuffer{
		data: (*C.uint8_t)(unsafe.Pointer(&fwData[0])),
		len:  C.uintptr_t(len(fwData)),
	}

	// Execute the mailbox command
	if err := mailboxExecute(model, 0x12345678, fwBuffer, nil); err != 0 {
		fmt.Printf("Error executing mailbox command: %d\n", err)
		return
	}

	fmt.Println("Mailbox command executed successfully!")
}

// Implement the Go wrapper function for the mailbox_execute C function
func mailboxExecute(model *C.struct_caliptra_model, cmd uint32, mboxTxBuffer *caliptraBuffer, mboxRxBuffer *caliptraBuffer) int {
	cMboxTxBuffer := mboxTxBuffer
	var cMboxRxBuffer *caliptraBuffer

	if mboxRxBuffer != nil {
		cMboxRxBuffer = mboxRxBuffer
	}

	// Call the C function
	ret := C.caliptra_mailbox_execute(model, C.uint32_t(cmd), cMboxTxBuffer, cMboxRxBuffer)

	return int(ret)
}
