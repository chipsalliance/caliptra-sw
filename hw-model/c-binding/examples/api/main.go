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
	data []byte
	len  uint32
}

// Define the Go struct for caliptra_model
type caliptraModel struct {
	// Add the necessary fields of caliptra_model if required
}

func main() {
	// Initialize caliptraModel
	model := &C.struct_caliptra_model{} // Create an instance of the C struct

	// Create a dummy buffer for firmware data (replace this with the actual data)
	fwData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	fwBuffer := &caliptraBuffer{
		data: fwData,
		len:  uint32(len(fwData)),
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
	cModel := model
	cMboxTxBuffer := (*C.struct_caliptra_buffer)(unsafe.Pointer(nil))
	var cMboxRxBuffer *C.struct_caliptra_buffer

	if mboxTxBuffer != nil {
		cMboxTxBuffer = (*C.struct_caliptra_buffer)(unsafe.Pointer(&mboxTxBuffer.data[0]))
	}

	if mboxRxBuffer != nil {
		cMboxRxBuffer = (*C.struct_caliptra_buffer)(unsafe.Pointer(mboxRxBuffer))
	}

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
