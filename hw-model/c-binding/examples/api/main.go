package main

// #cgo CFLAGS: -I./../out/debug
// #cgo LDFLAGS: -L./../out/debug -lcaliptra_hw_model_c_binding -ldl
// #include "../caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg.h"
// #include "caliptra_api.h"
// #include "caliptra_fuses.h"
// #include "caliptra_mbox.h"
//extern int caliptra_mailbox_write_fifo(struct caliptra_model *model, struct caliptra_buffer *buffer);
import "C"

import (
	"fmt"
	"unsafe"
)

// Define the Go struct for caliptra_buffer
type caliptraBuffer struct {
	data *C.uint8_t
	len  C.uintptr_t
	ptr  unsafe.Pointer
}

// Define the Go struct for caliptra_model
type caliptraModel struct {
	_unused [0]byte
}

func caliptraMailboxWriteFifo(model *caliptraModel, buffer *caliptraBuffer) int {
	// Dereference the pointer field in the Go struct
	cBuffer := (*C.caliptra_buffer)(buffer.ptr)

	// Call the C function
	ret := C.caliptra_mailbox_write_fifo(
		(*C.caliptra_model)(unsafe.Pointer(model)),
		cBuffer,
	)

	return int(ret)
}

func main() {
	// Initialize caliptraModel (replace this with your actual initialization logic)
	var model caliptraModel

	// Create a buffer for mailbox data (replace this with your actual data)
	bufferData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	buffer := &caliptraBuffer{
		data: (*C.uint8_t)(unsafe.Pointer(&bufferData[0])),
		len:  C.uintptr_t(len(bufferData)),
		ptr:  unsafe.Pointer(&buffer),
	}

	// Call caliptraMailboxWriteFifo
	result := caliptraMailboxWriteFifo(&model, buffer)
	if result != 0 {
		fmt.Printf("Error writing to mailbox: %d\n", result)
		return
	}

	fmt.Println("Mailbox write successful!")
}