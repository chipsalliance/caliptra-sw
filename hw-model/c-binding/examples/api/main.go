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

type caliptraBuffer struct {
	data *C.uint8_t
	len  C.uintptr_t
}

type caliptraModel struct {
	_unused [0]byte
}

func main() {
	model := &caliptraModel{} // Create an instance of the Go struct

	fwData := []C.uint8_t{0x01, 0x02, 0x03, 0x04, 0x05}
	fwBuffer := caliptraBuffer{
		data: (*C.uint8_t)(&fwData[0]),
		len:  C.uintptr_t(len(fwData)),
	}

	if err := mailboxExecute(model, 0x12345678, fwBuffer, nil); err != 0 {
		fmt.Printf("Error executing mailbox command: %d\n", err)
		return
	}

	fmt.Println("Mailbox command executed successfully!")
}

func mailboxExecute(model *caliptraModel, cmd C.uint32_t, mboxTxBuffer caliptraBuffer, mboxRxBuffer *caliptraBuffer) int {
	ret := C.caliptra_mailbox_execute((*C.struct_caliptra_model)(model), cmd, mboxTxBuffer, mboxRxBuffer)
	return int(ret)
}

func caliptraUploadFw(model *caliptraModel, fwBuffer caliptraBuffer) int {
	ret := C.caliptra_upload_fw((*C.struct_caliptra_model)(model), fwBuffer)
	return int(ret)
}
