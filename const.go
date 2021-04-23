package main

type actionType uint

const (
	CLEAN_CRL actionType = iota
	ADD_VALID_CRL
	ADD_INVALID_CRL
	ADD_FROZEN_CRL
	ADD_LOCKED_CRL
)

var mapper map[actionType]string

func init() {
	mapper = make(map[actionType]string)
	mapper[ADD_FROZEN_CRL] = "frozen"
	mapper[ADD_LOCKED_CRL] = "locked"
}

const (
	badCRL = `-----BEGIN X509 CRL-----
MIIDFDCCAfwCAQEwDQYJKoZIhvcNAQEFBQAwXzEjMCEGA1UEChMaU2FtcGxlIFNp
Z25lciBPcmdhbml6YXRpb24xGzAZBgNVBAsTElNhbXBsZSBTaWduZXIgVW5pdDEb
MBkGA1UEAxMSU2FtcGxlIFNpZ25lciBDZXJ0Fw0xMzAyMTgxMDMyMDBaFw0xMzAy
MTgxMDQyMDBaMIIBNjA8AgMUeUcXDTEzMDIxODEwMjIxMlowJjAKBgNVHRUEAwoB
AzAYBgNVHRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SBcNMTMwMjE4MTAyMjIy
WjAmMAoGA1UdFQQDCgEGMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFowPAIDFHlJ
Fw0xMzAyMTgxMDIyMzJaMCYwCgYDVR0VBAMKAQQwGAYDVR0YBBEYDzIwMTMwMjE4
MTAyMjAwWjA8AgMUeUoXDTEzMDIxODEwMjI0MlowJjAKBgNVHRUEAwoBATAYBgNV
HRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SxcNMTMwMjE4MTAyMjUxWjAmMAoG
A1UdFQQDCgEFMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFqgLzAtMB8GA1UdIwQY
MBaAFL4SAcyq6hGA2i6tsurHtfuf+a00MAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEB
BQUAA4IBAQBCIb6B8cN5dmZbziETimiotDy+FsOvS93LeDWSkNjXTG/+bGgnrm3a
QpgB7heT8L2o7s2QtjX2DaTOSYL3nZ/Ibn/R8S0g+EbNQxdk5/la6CERxiRp+E2T
UG8LDb14YVMhRGKvCguSIyUG0MwGW6waqVtd6K71u7vhIU/Tidf6ZSdsTMhpPPFu
PUid4j29U3q10SGFF6cCt1DzjvUcCwHGhHA02Men70EgZFADPLWmLg0HglKUh1iZ
WcBGtev/8VsUijyjsM072C6Ut5TwNyrrthb952+eKlmxLNgT0o5hVYxjXhtwLQsL
7QZhrypAM1DLYqQjkiDI7hlvt7QuDGTJ
-----END X509 CRL-----`
)

const (
	org1CACertPath = "/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem"
	// org1 ca's SKI: 7b523d6dcc5a0768dd8b18e463273470032036c4e1dcd7450e4ad26d0bcd89fa
	// [123 82 61 109 204 90 7 104 221 139 24 228 99 39 52 112 3 32 54 196 225 220 215 69 14 74 210 109 11 205 137 250]

	userCertTemplate = "/home/ubuntu/go/src/github.com/hyperledger/fabric/_debug/first-network-simple/crypto-config/peerOrganizations/org1.example.com/users/%[1]s@org1.example.com/msp/signcerts/%[1]s@org1.example.com-cert.pem"
)

const (
	USER1 = "User1"
	ADMIN = "Admin"
)
