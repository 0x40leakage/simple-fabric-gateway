/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package tls

import (
	stdTLS "crypto/tls"
	stdX509 "crypto/x509"
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	"time"
	"unsafe"

	gmTLS "github.com/Hyperledger-TWGC/ccs-gm/tls"
	ccsX509 "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/util"
	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	log "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/logbridge"
	fabricX509 "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/pkg/errors"
)

// DefaultCipherSuites is a set of strong TLS cipher suites
var DefaultCipherSuites = []uint16{
	stdTLS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	stdTLS.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	stdTLS.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	stdTLS.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	stdTLS.TLS_RSA_WITH_AES_128_GCM_SHA256,
	stdTLS.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled     bool     `skip:"true"`
	CertFiles   [][]byte `help:"A list of comma-separated PEM-encoded trusted certificate bytes"`
	Client      KeyCertFiles
	TlsCertPool *ccsX509.CertPool
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  []byte `help:"PEM-encoded key bytes when mutual authentication is enabled"`
	CertFile []byte `help:"PEM-encoded certificate bytes when mutual authenticate is enabled"`
}

func GetClientGmTLSConfig(cfg *ClientTLSConfig, csp core.CryptoSuite) (*gmTLS.Config, error) {
	var certs []gmTLS.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	log.Debugf("CA Files: %+v\n", cfg.CertFiles)
	log.Debugf("Client Cert File: %s\n", cfg.Client.CertFile)
	log.Debugf("Client Key File: %s\n", cfg.Client.KeyFile)

	if cfg.Client.CertFile != nil {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := util.LoadGMX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := fabricX509.NewCertPool()
	if len(cfg.CertFiles) == 0 {
		return nil, errors.New("No trusted root certificates for TLS were provided")
	}

	for _, cacert := range cfg.CertFiles {
		ok := rootCAPool.AppendCertsFromPEM(cacert)
		if !ok {
			return nil, errors.Errorf("Failed to process certificate from file %s", cacert)
		}
	}

	config := &gmTLS.Config{
		Certificates: certs,
		RootCAs:      (*ccsX509.CertPool)(unsafe.Pointer(rootCAPool)),
	}
	fmt.Println("config.ROotCAs ", config.RootCAs)
	return config, nil
}

// GetClientTLSConfig creates a tls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig, csp core.CryptoSuite) (*stdTLS.Config, error) {
	var certs []stdTLS.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	if cfg.Client.CertFile != nil {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := util.LoadX509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile, csp)
		if err != nil {
			return nil, err
		}

		certs = append(certs, *clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := cfg.TlsCertPool
	if rootCAPool == nil {
		rootCAPool, err := x509.SystemCertPool()
		if err != nil {
			log.Debugf("Failed to load system cert pool, switching to empty cert pool ")
			rootCAPool = x509.NewCertPool()
		}

		if len(cfg.CertFiles) == 0 {
			return nil, errors.New("No trusted root certificates for TLS were provided")
		}

		for _, cacert := range cfg.CertFiles {
			ok := rootCAPool.AppendCertsFromPEM(cacert)
			if !ok {
				return nil, errors.New("Failed to process certificate")
			}
		}
	}

	config := &stdTLS.Config{
		Certificates: certs,
		RootCAs:      (*stdX509.CertPool)(unsafe.Pointer(rootCAPool)),
	}

	return config, nil
}

func checkCertDates(certPEM []byte) error {
	log.Debug("Check client TLS certificate for valid dates")

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}
