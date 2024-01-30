module dpe

go 1.20

replace github.com/chipsalliance/caliptra-dpe/verification/testing => ../../dpe/verification/testing

replace github.com/chipsalliance/caliptra-dpe/verification/client => ../../dpe/verification/client

require (
	github.com/chipsalliance/caliptra-dpe/verification/client v0.0.0-20240126223313-d61940a4bf01
	github.com/chipsalliance/caliptra-dpe/verification/testing v0.0.0-20240126223313-d61940a4bf01
)

require (
	github.com/github/smimesign v0.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.10.1 // indirect
	github.com/google/go-tdx-guest v0.2.3-0.20231011100059-4cf02bed9d33 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tpm-tools v0.4.2 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/weppos/publicsuffix-go v0.30.2-0.20230730094716-a20f9abcc222 // indirect
	github.com/zmap/zcrypto v0.0.0-20231219022726-a1f61fb1661c // indirect
	github.com/zmap/zlint/v3 v3.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/exp v0.0.0-20240119083558-1b970713d09a // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)
