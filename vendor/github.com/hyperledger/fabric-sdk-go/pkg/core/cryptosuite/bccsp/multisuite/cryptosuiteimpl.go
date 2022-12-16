/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package multisuite

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/pkcs11"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sdf"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/sw"
	"github.com/pkg/errors"
)

var (
	//Opts used to judge the choice of SW, GM, PKCS11 or SDF
	Opts string
	//Algorithm used to judge the choice of SW or GM
	Algorithm string

	// Algorithm used to judge the choice of SW or GM
	// ImplType string
)

//GetSuiteByConfig returns cryptosuite adaptor for bccsp loaded according to given config
func GetSuiteByConfig(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	switch config.SecurityProvider() {
	case "sw":
		// swVendor := config.SecurityImplType()
		// if !cryptocfg.IsValidSWGMVendor(swVendor) {
		// 	Opts = "SW"
		// } else {
		// 	Opts = "GM"
		// }
		return sw.GetSuiteByConfig(config)
	case "pkcs11":
		Opts = "PKCS11"
		Algorithm = config.SecurityProviderAlgorithm()
		return pkcs11.GetSuiteByConfig(config)
	case "sdf":
		Opts = "SDF"
		return sdf.GetSuiteByConfig(config)
	}

	return nil, errors.Errorf("Unsupported security provider requested: %s", config.SecurityProvider())
}
