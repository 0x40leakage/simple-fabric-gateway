package pkcs11

import (
	"errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

type sm4PrivateKey struct {
	key []byte
	ski []byte
}

func (k *sm4PrivateKey) Bytes() (raw []byte, err error) {
	return k.key, nil
}

func (k *sm4PrivateKey) SKI() (ski []byte) {
	// Hash it
	return k.ski
}

func (k *sm4PrivateKey) Symmetric() bool {
	return true
}

func (k *sm4PrivateKey) Private() bool {
	return true
}

func (k *sm4PrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key.")
}
