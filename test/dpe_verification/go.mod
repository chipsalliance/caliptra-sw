module dpe

go 1.20

replace github.com/chipsalliance/caliptra-dpe/verification/testing => ../../dpe/verification/testing

replace github.com/chipsalliance/caliptra-dpe/verification/client => ../../dpe/verification/client

replace github.com/chipsalliance/caliptra-dpe/verification/sim => ../../dpe/verification/sim

require (
	github.com/chipsalliance/caliptra-dpe/verification/client v0.0.0-20240305022518-f4e3dd792a5c
	github.com/chipsalliance/caliptra-dpe/verification/testing v0.0.0-20240227181801-29d5ca397c66
)

require (
	github.com/chipsalliance/caliptra-dpe/verification/sim v0.0.0-20240305022518-f4e3dd792a5c // indirect
	github.com/github/smimesign v0.2.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.11.0 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tpm-tools v0.4.3 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/weppos/publicsuffix-go v0.30.2-0.20230730094716-a20f9abcc222 // indirect
	github.com/zmap/zcrypto v0.0.0-20231219022726-a1f61fb1661c // indirect
	github.com/zmap/zlint/v3 v3.6.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/exp v0.0.0-20240222234643-814bf88cf225 // indirect
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)
