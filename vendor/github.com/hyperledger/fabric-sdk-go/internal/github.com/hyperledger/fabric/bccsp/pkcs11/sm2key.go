package pkcs11

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

type sm2PrivateKey struct {
	ski []byte
	pub sm2PublicKey
}

func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

func (k *sm2PrivateKey) SKI() []byte {
	return k.ski
}

func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

func (k *sm2PrivateKey) Private() bool {
	return true
}

func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &k.pub, nil
}

type sm2PublicKey struct {
	ski []byte
	pub *crypto.PublicKey
}

func (k *sm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pub)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}

	return
}

func (k *sm2PublicKey) SKI() []byte {
	return k.ski
}

func (k *sm2PublicKey) Symmetric() bool {
	return false
}

func (k *sm2PublicKey) Private() bool {
	return false
}

func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
