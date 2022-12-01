// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"path"
	"strings"

	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/x509"
	"github.com/pkg/errors"
)

// ConfigureBCCSP configures BCCSP, using
func ConfigureBCCSP(optsPtr **factory.FactoryOpts, mspDir, homeDir string) error {
	var err error
	if optsPtr == nil {
		return errors.New("nil argument not allowed")
	}
	opts := *optsPtr
	if opts == nil {
		opts = &factory.FactoryOpts{}
	}
	if opts.ProviderName == "" {
		opts.ProviderName = "SW"
	}
	if strings.ToUpper(opts.ProviderName) == "SW" {
		if opts.SwOpts == nil {
			opts.SwOpts = &factory.SwOpts{}
		}
		if opts.SwOpts.HashFamily == "" {
			opts.SwOpts.HashFamily = "SHA2"
		}
		if opts.SwOpts.SecLevel == 0 {
			opts.SwOpts.SecLevel = 256
		}
		if opts.SwOpts.FileKeystore == nil {
			opts.SwOpts.FileKeystore = &factory.FileKeystoreOpts{}
		}
		// The mspDir overrides the KeyStorePath; otherwise, if not set, set default
		if mspDir != "" {
			opts.SwOpts.FileKeystore.KeyStorePath = path.Join(mspDir, "keystore")
		} else if opts.SwOpts.FileKeystore.KeyStorePath == "" {
			opts.SwOpts.FileKeystore.KeyStorePath = path.Join("msp", "keystore")
		}
	} else if strings.ToUpper(opts.ProviderName) == "GM" {
		if opts.GmOpts == nil {
			opts.GmOpts = &factory.GmOpts{}
		}
		if opts.GmOpts.FileKeystore == nil {
			opts.GmOpts.FileKeystore = &factory.FileKeystoreOpts{}
		}
		if mspDir != "" {
			opts.GmOpts.FileKeystore.KeyStorePath = path.Join(mspDir, "keystore")
		} else if opts.GmOpts.FileKeystore.KeyStorePath == "" {
			opts.GmOpts.FileKeystore.KeyStorePath = path.Join("msp", "keystore")
		}
		err := gm.InitGMPlugin(opts.GmOpts.ImplType, opts.GmOpts.IP, opts.GmOpts.Port, opts.GmOpts.Password, opts.GmOpts.Library)
		if err != nil {
			return err
		}
		x509.InitX509("ccsgm")
	}
	err = MakeFileNamesAbsolute(opts, homeDir)
	if err != nil {
		return errors.WithMessage(err, "Failed to make BCCSP files absolute")
	}
	log.Debugf("Initializing BCCSP: %+v", opts)
	if opts.SwOpts != nil {
		log.Debugf("Initializing BCCSP with software options %+v", opts.SwOpts)
	}
	if opts.ProviderName == "PKCS11" && opts.Pkcs11Opts != nil {
		if opts.Pkcs11Opts.Algorithm == "GM" {
			x509.InitX509("ccsgm")
		}
		log.Debugf("Initializing BCCSP with PKCS11 options %+v", opts.Pkcs11Opts)
	}
	if opts.ProviderName == "SDF" && opts.SdfOpts != nil {
		x509.InitX509("ccsgm")
		log.Debugf("Initializing BCCSP with SDF options %+v", opts.SdfOpts)
	}
	*optsPtr = opts
	return nil
}
