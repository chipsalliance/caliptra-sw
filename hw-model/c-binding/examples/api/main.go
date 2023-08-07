package main

// #cgo CFLAGS: -I./../out/debug
// #cgo LDFLAGS: -L./../out/debug -lcaliptra_hw_model_c_binding
// #include "../caliptra-rtl/src/soc_ifc/rtl/caliptra_top_reg.h"
// #include "caliptra_api.h"
// #include "caliptra_fuses.h"
// #include "caliptra_mbox.h"
import "C"
import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// Define Go equivalent structures for the mailbox and profile descriptor.
type CaliptraModel C.struct_caliptra_model
type CaliptraBuffer C.struct_caliptra_buffer

type ProfileDescriptor struct {
	Name                     string
	DpeSpecVersion           uint32
	MaxMessageSize           uint32
	UsesMultiPartMessages    bool
	SupportsConcurrentOps    bool
	SupportsEncryptedSessions bool
	SupportsDerivedSessions  bool
	MaxSessions              uint32
	SessionProtocol          string
	SupportsSessionSync      bool
	SessionSyncPolicy        string
	SupportsSessionMigration bool
	SessionMigrationProtocol string
	SupportsDefaultContext   bool
	SupportsContextHandles   bool
	MaxContextsPerSession    uint32
	MaxContextHandleSize     uint32
	SupportsAutoInit         bool
	SupportsSimulation       bool
	SupportsAttestation      bool
	SupportsSealing          bool
	SupportsGetProfile       bool
}

// Helper function to convert a uint32 to a byte slice.
func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

func parseProfileDescriptor(data []byte) (*ProfileDescriptor, error) {
	// Implement parsing of the CBOR-encoded profile descriptor.
	// You need to replace this with actual parsing logic.
	// For decoding CBOR in Go, you can use libraries like "github.com/fxamacker/cbor" or "encoding/json".

	// Example implementation:
	profile := &ProfileDescriptor{}
	profile.Name = "Sample Profile"
	profile.DpeSpecVersion = 1
	profile.MaxMessageSize = 4096
	profile.UsesMultiPartMessages = true
	profile.SupportsConcurrentOps = true
	profile.SupportsEncryptedSessions = false
	// ... continue parsing other attributes ...

	return profile, nil
}

func main() {
	// Initialize your CaliptraModel instance.
	model := C.struct_caliptra_model{} // Replace this with actual initialization code.

	// Execute the getProfile command
	mboxTxBuffer := CaliptraBuffer{}
	mboxRxBuffer := CaliptraBuffer{}
	cmd := C.uint32_t(0x6) // Replace this with the actual command code for getProfile

	err := caliptraMailboxExecute(&model, cmd, &mboxTxBuffer, &mboxRxBuffer)
	if err != nil {
		fmt.Println("Error executing getProfile:", err)
		return
	}

	// Parse the received profile descriptor
	profileDescriptor, err := parseProfileDescriptor(C.GoBytes(unsafe.Pointer(mboxRxBuffer.data), C.int(mboxRxBuffer.len)))
	if err != nil {
		fmt.Println("Error parsing profile descriptor:", err)
		return
	}

	// Use the profile descriptor data as needed.
	fmt.Printf("Profile Descriptor:\n%+v\n", profileDescriptor)
}

// Implement the C functions using Cgo
func caliptraMailboxWrite(model *C.struct_caliptra_model, data []byte) error {
	// Implement the mailbox write operation using Cgo.
	// You need to replace this with actual implementation to write data to the mailbox.
	return nil
}

func caliptraMailboxRead(model *C.struct_caliptra_model, data []byte) error {
	// Implement the mailbox read operation using Cgo.
	// You need to replace this with actual implementation to read data from the mailbox.
	return nil
}

func caliptraMailboxExecute(model *C.struct_caliptra_model, cmd C.uint32_t, txBuffer, rxBuffer *CaliptraBuffer) error {
    // Parameter check
    if model == nil {
        return fmt.Errorf("invalid model")
    }

    // If mbox already locked return
    if bool(C.caliptra_mbox_is_lock(model)) {
        return fmt.Errorf("mailbox is locked")
    }

    // Write Cmd and Tx Buffer
    if err := caliptraMailboxWrite(model, uint32ToBytes(uint32(cmd))); err != nil {
        return fmt.Errorf("failed to write command to mailbox: %w", err)
    }
    if err := caliptraMailboxWrite(model, C.GoBytes(unsafe.Pointer(txBuffer.data), C.int(txBuffer.len))); err != nil {
        return fmt.Errorf("failed to write tx buffer to mailbox: %w", err)
    }

    // Set Execute bit
    C.caliptra_mbox_write_execute(model, C.bool(true))

    // Keep stepping until mbox status is busy
    for C.caliptra_mbox_read_status(model) == CALIPTRA_MBOX_STATUS_BUSY {
        // Implement stepping model.
        // You need to replace this with the actual implementation to step the model.
    }

    // Check the Mailbox Status
    status := C.caliptra_mbox_read_status(model)
    if status == CALIPTRA_MBOX_STATUS_CMD_FAILURE {
        C.caliptra_mbox_write_execute(model, C.bool(false))
        return fmt.Errorf("command execution failed")
    } else if status == CALIPTRA_MBOX_STATUS_CMD_COMPLETE {
        C.caliptra_mbox_write_execute(model, C.bool(false))
        return nil
    } else if status != CALIPTRA_MBOX_STATUS_DATA_READY {
        return fmt.Errorf("unexpected mailbox status")
    }

    // Read Mbox out Data Len
    dlenBytes := make([]byte, 4)
    if err := caliptraMailboxRead(model, dlenBytes); err != nil {
        return fmt.Errorf("failed to read mbox data length: %w", err)
    }
    dlen := binary.LittleEndian.Uint32(dlenBytes)

    // Convert dlen to C type (ulong)
    dlenC := C.ulong(dlen)

    // Read Buffer
    rxBuffer.data = (*C.uint8_t)(C.malloc(C.size_t(dlenC)))
    rxBuffer.len = dlenC
    if err := caliptraMailboxRead(model, C.GoBytes(unsafe.Pointer(rxBuffer.data), C.int(rxBuffer.len))); err != nil {
        return fmt.Errorf("failed to read mbox rx buffer: %w", err)
    }

    // Execute False
    C.caliptra_mbox_write_execute(model, C.bool(false))

    // mbox_fsm_ps isn't updated immediately after execute is cleared (!?),
    // so step an extra clock cycle to wait for fm_ps to update
    // Implement stepping model.
    // You need to replace this with the actual implementation to step the model.

    if C.caliptra_mbox_read_status_fsm(model) != CALIPTRA_MBOX_STATUS_FSM_IDLE {
        return fmt.Errorf("unexpected mailbox fsm status")
    }

    return nil
}

// Constants for mailbox status.
const (
	CALIPTRA_MBOX_STATUS_BUSY        = 1
	CALIPTRA_MBOX_STATUS_CMD_COMPLETE = 2
	CALIPTRA_MBOX_STATUS_DATA_READY   = 3
	CALIPTRA_MBOX_STATUS_CMD_FAILURE  = 4
	CALIPTRA_MBOX_STATUS_FSM_IDLE     = 0
)
