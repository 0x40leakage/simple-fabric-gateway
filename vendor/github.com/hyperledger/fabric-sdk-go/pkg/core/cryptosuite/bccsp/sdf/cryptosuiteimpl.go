package sdf

import (
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	bccspSDF "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/wrapper"
)

var logger = logging.NewLogger("fabsdk/core")

//GetSuiteByConfig returns cryptosuite adaptor for bccsp loaded according to given config
func GetSuiteByConfig(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	// TODO: delete this check?
	if config.SecurityProvider() != "sdf" {
		return nil, errors.Errorf("Unsupported BCCSP Provider: %s", config.SecurityProvider())
	}

	opts := getOptsByConfig(config)
	csp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}

	return &wrapper.CryptoSuite{BCCSP: csp}, nil
}

func getBCCSPFromOpts(config *bccspSDF.FactoryOpts) (bccsp.BCCSP, error) {
	f := &bccspSDF.SDFFactory{}
	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

func getOptsByConfig(c core.CryptoSuiteConfig) *bccspSDF.FactoryOpts {
	opts := &bccspSDF.FactoryOpts{
		ProviderName: "SDF",
		SdfOpts: &factory.SdfOpts{
			Library:    c.SecurityLibrary(),
			PrivatePin: c.SecurityProviderPin(),
		},
	}

	logger.Debug("Initialized SDF cryptosuite")

	return opts
}
