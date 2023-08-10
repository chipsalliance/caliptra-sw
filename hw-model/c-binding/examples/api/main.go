package main

// #cgo CFLAGS: -I./../out/debug -std=c99
// #cgo LDFLAGS: -L./../out/debug -lcaliptra_hw_model_c_binding -ldl
// #include "../caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg.h"
// #include "caliptra_api.h"
// #include "caliptra_fuses.h"
// #include "caliptra_mbox.h"
// extern int caliptra_mailbox_write_fifo(struct caliptra_model *model, struct caliptra_buffer *buffer);
import "C"

import (
	"fmt"
	"unsafe"
)

func main() {
	// Create a C struct
	var me C.struct_person
	me.name = C.CString("Tony")
	me.age = 23

	// Call the C function
	a := C.greet(&me)
	fmt.Println(a)

	// Create a caliptra_buffer struct from a []byte
	romData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	rom := C.caliptra_buffer{
		data: (*C.uint8_t)(unsafe.Pointer(&romData[0])),
		len:  C.uintptr_t(len(romData)),
	}

	// Create a caliptra_model struct
	var model C.caliptra_model
	//model._unused = [1]C.uint8_t{} // Initialize as needed

	// Call the caliptra_mailbox_write_fifo function
	ret := C.caliptra_mailbox_write_fifo(&model, &rom)

	fmt.Println(ret)
}
