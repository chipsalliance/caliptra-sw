// Licensed under the Apache-2.0 license

package dpe

import (
	"os"
	"testing"

	"github.com/chipsalliance/caliptra-dpe/verification/client"
	dpetesting "github.com/chipsalliance/caliptra-dpe/verification/testing"
)

func TestRunAll(t *testing.T) {
	var d client.TestDPEInstance = &CptraModel{}

	// Power on Caliptra
	err := d.PowerOn()
	if err != nil {
		t.Fatalf("Could not power on the target: %v", err)
	}
	defer d.PowerOff()

	for _, test := range dpetesting.AllTestCases {
		t.Run(test.Name, func(t *testing.T) {
			if !client.HasSupportNeeded(d, test.SupportNeeded) {
				t.Skipf("Warning: Target does not have required support, skipping test.")
			}

			profile, err := client.GetTransportProfile(d)
			if err != nil {
				t.Fatalf("Could not get profile: %v", err)
			}

			c, err := client.NewClient(d, profile)
			if err != nil {
				t.Fatalf("Could not initialize client: %v", err)
			}

			test.Run(d, c, t)
		})
	}
}

func TestMain(m *testing.M) {
	exitVal := m.Run()
	os.Exit(exitVal)
}
