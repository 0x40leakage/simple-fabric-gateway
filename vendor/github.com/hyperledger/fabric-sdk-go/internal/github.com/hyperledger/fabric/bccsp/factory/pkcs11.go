// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"strings"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/pkg/errors"
)

const pkcs11Enabled = true

// FactoryOpts holds configuration information used to initialize factory implementations
type FactoryOpts struct {
	ProviderName string             `mapstructure:"default" json:"default" yaml:"Default"`
	SwOpts       *SwOpts            `mapstructure:"SW,omitempty" json:"SW,omitempty" yaml:"SwOpts"`
	GmOpts       *GmOpts            `mapstructure:"GM,omitempty" json:"GM,omitempty" yaml:"GmOpts"`
	PluginOpts   *PluginOpts        `mapstructure:"PLUGIN,omitempty" json:"PLUGIN,omitempty" yaml:"PluginOpts"`
	Pkcs11Opts   *pkcs11.PKCS11Opts `mapstructure:"PKCS11,omitempty" json:"PKCS11,omitempty" yaml:"PKCS11"`
	SdfOpts      *SdfOpts           `mapstructure:"SDF,omitempty" json:"SDF,omitempty" yaml:"SDF"`
}

// InitFactories must be called before using factory interfaces
// It is acceptable to call with config = nil, in which case
// some defaults will get used
// Error is returned only if defaultBCCSP cannot be found
func InitFactories(config *FactoryOpts) error {
	factoriesInitOnce.Do(func() {
		factoriesInitError = initFactories(config)
	})

	return factoriesInitError
}

func initFactories(config *FactoryOpts) error {
	// Take some precautions on default opts
	if config == nil {
		config = GetDefaultOpts()
	}

	if config.ProviderName == "" {
		config.ProviderName = "SW"
	}

	if config.SwOpts == nil {
		config.SwOpts = GetDefaultOpts().SwOpts
	}

	// Initialize factories map
	bccspMap = make(map[string]bccsp.BCCSP)
	var f BCCSPFactory
	var err error

	if config.ProviderName == "SW" {
		f = &SWFactory{}
		err := initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing BCCSP.")
		}
	}
	if config.ProviderName == "GM" {
		f = &GMFactory{}
		var err error
		if config.GmOpts == nil {
			config.GmOpts = GetDefaultGMOpts().GmOpts
			err = gm.InitGMPlugin(config.GmOpts.ImplType)
		} else {
			switch strings.ToLower(config.GmOpts.ImplType) {
			case "", "ccsgm":
				err = gm.InitGMPlugin(config.GmOpts.ImplType)
			case "xin_an":
				err = gm.InitGMPlugin(config.GmOpts.ImplType, config.GmOpts.IP, config.GmOpts.Port, config.GmOpts.Password, config.GmOpts.Library)
			default:
				err = errors.Errorf("unrecognized gm plugin type: %s", config.GmOpts.ImplType)
			}
		}
		if err != nil {
			return errors.Wrapf(err, "invalid config, InitGMPlugin failed")
		}
		err = initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing BCCSP.")
		}
	}

	// PKCS11-Based BCCSP
	if config.ProviderName == "PKCS11" {
		logger.Debug("config.ProviderName :", config.ProviderName)
		f = &PKCS11Factory{}
		err = initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing PKCS11.BCCSP %s", factoriesInitError)
		}
	}

	// BCCSP Plugin
	if config.ProviderName == "PLUGIN" && config.PluginOpts != nil {
		f = &PluginFactory{}
		err := initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing PLUGIN.BCCSP %s", factoriesInitError)
		}
	}

	// BCCSP SDF
	if config.ProviderName == "SDF" {
		f = &SDFFactory{}
		err := initBCCSP(f, config)
		if err != nil {
			factoriesInitError = errors.Wrapf(err, "Failed initializing SDF.BCCSP %s", factoriesInitError)
		}
	}
	var ok bool
	defaultBCCSP, ok = bccspMap[config.ProviderName]
	if !ok {
		return errors.Errorf("Could not find default `%s` BCCSP for %s", config.ProviderName, factoriesInitError)
	}

	return nil
}

// GetBCCSPFromOpts returns a BCCSP created according to the options passed in input.
func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.ProviderName {
	case "SW":
		f = &SWFactory{}
	case "PKCS11":
		f = &PKCS11Factory{}
	case "PLUGIN":
		f = &PluginFactory{}
	case "GM":
		f = &GMFactory{}
	case "SDF":
		f = &SDFFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.ProviderName)
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}
