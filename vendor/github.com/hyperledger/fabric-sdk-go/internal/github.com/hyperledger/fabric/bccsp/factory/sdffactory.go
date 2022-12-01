package factory

import (
	"errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sdf"
)

const (
	SDFBasedFactoryName = "SDF"
)

type SDFFactory struct{}

// Name returns the name of this factory
func (f *SDFFactory) Name() string {
	return SDFBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *SDFFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil {
		return nil, errors.New("invalid config. It must not be nil")
	}
	if config.SdfOpts == nil {
		config.SdfOpts = &SdfOpts{
			Library:    "/usr/local/lib/libSDF.so",
			PrivatePin: "a1234567",
		}
	}
	if config.ProviderName == "SDF" {
		return sdf.New(config.SdfOpts.Library, config.SdfOpts.PrivatePin)
	}

	return nil, errors.New("Invalid config. It will set to sdf")
}

type SdfOpts struct {
	Library          string `mapstructure:"library" json:"library"`
	PrivatePin       string `mapstructure:"privatepin" json:"privatepin" yaml:"PrivatePin"`
}
