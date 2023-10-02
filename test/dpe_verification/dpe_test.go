// Licensed under the Apache-2.0 license

package dpe

import (
	"github.com/chipsalliance/caliptra-dpe/verification"
	"os"
	"testing"
)

func TestRunAll(t *testing.T) {
	for _, test := range verification.TestCases {
		t.Run(test.Name, func(t *testing.T) {
			var d verification.TestDPEInstance = &CptraModel{}

			if !verification.HasSupportNeeded(d, test.SupportNeeded) {
				t.Skipf("Warning: Target does not have required support, skipping test.")
			}

			test.Run(d, t)
		})
	}
}

func TestMain(m *testing.M) {
	exitVal := m.Run()
	os.Exit(exitVal)
}
