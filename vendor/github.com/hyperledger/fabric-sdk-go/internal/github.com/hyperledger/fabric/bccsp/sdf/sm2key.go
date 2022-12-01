package sdf

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/pkg/errors"
)

type sm2Key struct {
	ski []byte
	pub *crypto.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2Key) Bytes() ([]byte, error) {
	raw, err := x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed marshalling key")
	}
	return raw, nil
}

// SKI returns the subject key identifier of this key.
func (k *sm2Key) SKI() []byte {
	return k.ski
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *sm2Key) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *sm2Key) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *sm2Key) PublicKey() (bccsp.Key, error) {
	return k, nil
}
