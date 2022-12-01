// +build !pkcs11

/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package factory

import (
	"strings"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/pkcs11"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/pkg/errors"
)

const pkcs11Enabled = false

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
	// Software-Based BCCSP
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

	// BCCSP Plugin
	if config.ProviderName == "PLUGIN" && config.PluginOpts != nil {
		f := &PluginFactory{}
		err := initBCCSP(f, config)
		if err != nil {
			return errors.Wrapf(err, "Failed initializing PLUGIN.BCCSP")
		}
	}

	var ok bool
	defaultBCCSP, ok = bccspMap[config.ProviderName]
	if !ok {
		return errors.Errorf("Could not find default `%s` BCCSP", config.ProviderName)
	}
	return nil
}

// GetBCCSPFromOpts returns a BCCSP created according to the options passed in input.
func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.ProviderName {
	case "SW":
		f = &SWFactory{}
	case "PLUGIN":
		f = &PluginFactory{}
	case "GM":
		f = &GMFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.ProviderName)
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}
