package lib

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/api"
)

type lockResponseNet struct {
	LockedCerts []api.LockedCert
	CRL         string
}

const (
	// Locked is the status of a locked certificate
	Locked CertificateStatus = "locked"
)
