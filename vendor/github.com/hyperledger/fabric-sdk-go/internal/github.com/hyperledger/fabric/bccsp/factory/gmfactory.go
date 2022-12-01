/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
)

const (
	GMBasedFactoryName = "GM"
)

// GMFactory is the factory of the software-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GMBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.GmOpts == nil {
		return nil, errors.New("invalid config. It must not be nil")
	}
	if config.ProviderName == "GM" {
		gmOpts := config.GmOpts
		var ks bccsp.KeyStore
		if gmOpts.FileKeystore != nil {
			fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, gmOpts.ImplType, false)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize software key store: %s", err)
			}
			ks = fks
		} else {
			// Default to DummyKeystore
			ks = gm.NewDummyKeyStore()
		}
		return gm.New(ks, gmOpts.ImplType)
	}
	return nil, errors.New("Invalid config. It will set to gm")
}

// SwOpts contains options for the SWFactory
type GmOpts struct {
	// Default algorithms when not specified (Deprecated?)
	ImplType      string             `mapstructure:"impltype" json:"impltype" yaml:"ImplType"`
	Library       string             `mapstructure:"library" json:"library" yaml:"Library"`
	IP            string             `mapstructure:"ip" json:"ip" yaml:"IP"`
	Port          string             `mapstructure:"port" json:"port" yaml:"Port"`
	Password      string             `mapstructure:"password" json:"password" yaml:"password"`
	FileKeystore  *FileKeystoreOpts  `mapstructure:"filekeystore,omitempty" json:"filekeystore,omitempty" yaml:"FileKeyStore"`
	DummyKeystore *DummyKeystoreOpts `mapstructure:"dummykeystore,omitempty" json:"dummykeystore,omitempty"`
	InmemKeystore *InmemKeystoreOpts `mapstructure:"inmemkeystore,omitempty" json:"inmemkeystore,omitempty"`
}
