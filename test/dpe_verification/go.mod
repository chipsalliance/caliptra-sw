module dpe

go 1.20

replace github.com/chipsalliance/caliptra-dpe/verification => ../../dpe/verification

require github.com/chipsalliance/caliptra-dpe/verification v0.0.0-20231002193428-bb19016edf87

require (
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/weppos/publicsuffix-go v0.30.1-0.20230422193905-8fecedd899db // indirect
	github.com/zmap/zcrypto v0.0.0-20230422215203-9a665e1e9968 // indirect
	github.com/zmap/zlint/v3 v3.4.1 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/text v0.8.0 // indirect
)
