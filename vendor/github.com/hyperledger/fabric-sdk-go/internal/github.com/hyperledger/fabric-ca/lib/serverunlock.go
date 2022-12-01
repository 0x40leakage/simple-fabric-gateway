package lib

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/api"
)

type unlockResponseNet struct {
	UnlockedCerts []api.UnlockedCert
	CRL           string
}
