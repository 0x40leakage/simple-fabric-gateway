package util

import (
	stdx509 "crypto/x509"
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

func ToFabricX509(certificate *stdx509.Certificate) *x509.Certificate {
	return (*x509.Certificate)(unsafe.Pointer(certificate))
}
