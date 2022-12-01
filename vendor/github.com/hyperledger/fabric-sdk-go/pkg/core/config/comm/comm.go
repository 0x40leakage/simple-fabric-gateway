/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	gmTLS "github.com/Hyperledger-TWGC/ccs-gm/tls"
	ccsX509 "github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/pkg/errors"
)

// TLSConfig returns the appropriate config for TLS including the root CAs,
// certs for mutual TLS, and server host override. Works with certs loaded either from a path or embedded pem.
func TLSConfig(cert *ccsX509.Certificate, serverName string, config fab.EndpointConfig) (*gmTLS.Config, error) {
	if cert != nil {
		config.TLSCACertPool().Add(cert)
	}

	certPool, err := config.TLSCACertPool().Get()
	if err != nil {
		return nil, err
	}

	if cert != nil {
		if _, ok := cert.PublicKey.(*sm2.PublicKey); ok {
			return &gmTLS.Config{RootCAs: certPool, Certificates: config.TLSClientCerts(), ServerName: serverName, GMSupport: &gmTLS.GMSupport{}, MinVersion: gmTLS.VersionGMSSL}, nil
		}
	}

	return &gmTLS.Config{RootCAs: certPool, Certificates: config.TLSClientCerts(), ServerName: serverName}, nil
}

// TLSCertHash is a utility method to calculate the SHA256 hash of the configured certificate (for usage in channel headers)
func TLSCertHash(config fab.EndpointConfig) ([]byte, error) {
	certs := config.TLSClientCerts()
	if len(certs) == 0 {
		return computeHash([]byte(""))
	}

	cert := certs[0]
	if len(cert.Certificate) == 0 {
		return computeHash([]byte(""))
	}

	return computeHash(cert.Certificate[0])
}

//computeHash computes hash for given bytes using underlying cryptosuite default
func computeHash(msg []byte) ([]byte, error) {
	h, err := cryptosuite.GetDefault().Hash(msg, cryptosuite.GetSHA256Opts())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to compute tls cert hash")
	}
	return h, err
}
