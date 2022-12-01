/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"strings"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/wrapper"
	"github.com/pkg/errors"
)

var logger = logging.NewLogger("fabsdk/core")

// Factories' Initialization Error
var factoriesInitError error

//GetSuiteByConfig returns cryptosuite adaptor for bccsp loaded according to given config
func GetSuiteByConfig(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	// TODO: delete this check?
	if config.SecurityProvider() != "gm" {
		return nil, errors.Errorf("Unsupported BCCSP Provider: %s", config.SecurityProvider())
	}

	opts := getOptsByConfig(config)
	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

//GetSuiteWithDefaultEphemeral returns cryptosuite adaptor for bccsp with default ephemeral options (intended to aid testing)
func GetSuiteWithDefaultEphemeral() (core.CryptoSuite, error) {
	opts := getEphemeralOpts()

	csp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(csp), nil
}

func getBCCSPFromOpts(config *factory.FactoryOpts) (csp bccsp.BCCSP, err error) {
	f := &factory.GMFactory{}

	//如果是国密，需要针对参数加载对应plugin
	switch strings.ToLower(config.GmOpts.ImplType) {
	case "", "ccsgm":
		err = gm.InitGMPlugin(config.GmOpts.ImplType)
	case "xin_an":
		err = gm.InitGMPlugin(config.GmOpts.ImplType, config.GmOpts.IP, config.GmOpts.Port, config.GmOpts.Password, config.GmOpts.Library)
	}
	if err != nil {
		return nil, errors.Wrapf(errors.Errorf("unrecognized gm plugin type: %s", config.GmOpts.ImplType), "Failed initializing BCCSP.")
	}

	csp, err = f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

// GetSuite returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func GetSuite(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (core.CryptoSuite, error) {
	csp, err := sw.NewWithParams(securityLevel, hashFamily, keyStore)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(csp), nil
}

//GetOptsByConfig Returns Factory opts for given SDK config
func getOptsByConfig(c core.CryptoSuiteConfig) *factory.FactoryOpts {
	opts := &factory.FactoryOpts{
		ProviderName: "GM",
		GmOpts: &factory.GmOpts{
			ImplType: c.SecurityImplType(),
			Library:  c.SecurityLibrary(),
			IP:       c.SecurityIP(),
			Port:     c.SecurityPort(),
			Password: c.SecurityPassword(),
			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: c.KeyStorePath(),
			},
		},
	}
	logger.Debug("Initialized GM cryptosuite")

	return opts
}

func getEphemeralOpts() *factory.FactoryOpts {
	opts := &factory.FactoryOpts{
		ProviderName: "GM",
		GmOpts: &factory.GmOpts{
			ImplType: "ccsgm",
		},
	}
	logger.Debug("Initialized ephemeral SW cryptosuite with default opts")

	return opts
}
