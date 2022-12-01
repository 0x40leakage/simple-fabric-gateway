package gm

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

// xinan server public key
type xinAnPrivateKey struct {
	xinAnPubKey
	DN  string
	csr []byte
}

func (k *xinAnPrivateKey) Bytes() ([]byte, error) {
	return k.csr, nil
}

func (k *xinAnPrivateKey) SKI() []byte {
	return k.cert.Raw
}

func (k *xinAnPrivateKey) Symmetric() bool {
	return false
}

func (k *xinAnPrivateKey) Private() bool {
	return true
}

func (k *xinAnPrivateKey) PublicKey() (bccsp.Key, error) {
	return &k.xinAnPubKey, nil
}

// xinan server public key
type xinAnPubKey struct {
	cert *x509.Certificate
}

func (k *xinAnPubKey) Bytes() ([]byte, error) {
	pk := k.cert.PublicKey
	var pkk interface{}

	switch pk.(type) {
	case *sm2.PublicKey, *crypto.PublicKey, *ecdsa.PublicKey:
		pkk = pk
	}

	if pkk == nil {
		logger.Errorf("invalid raw material. publicKey must be *crypto.PublicKey or *ecdsa.PublicKey or *sm2.PublicKey")
		return nil, fmt.Errorf("invalid raw material. publicKey must be *crypto.PublicKey or *ecdsa.PublicKey or *sm2.PublicKey")
	}
	return x509.MarshalPKIXPublicKey(pkk)
}

func (k *xinAnPubKey) SKI() []byte {
	return k.cert.Raw
}

func (k *xinAnPubKey) Symmetric() bool {
	return false
}

func (k *xinAnPubKey) Private() bool {
	return false
}

func (k *xinAnPubKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
