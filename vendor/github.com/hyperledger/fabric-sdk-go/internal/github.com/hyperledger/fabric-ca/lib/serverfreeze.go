/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/api"
)

type freezeResponseNet struct {
	FrozenCerts []api.FrozenCert
	CRL         string
}

const (
	// Frozen is the status of a frozen certificate
	Frozen CertificateStatus = "frozen"
)
