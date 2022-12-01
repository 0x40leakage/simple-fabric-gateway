package sdf

import (
	"errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

type sm4Key struct {
	ski []byte
	key []byte
}

func (k *sm4Key) Bytes() (raw []byte, err error) {
	return k.key, nil
}

func (k *sm4Key) SKI() []byte {
	return k.ski
}

func (k *sm4Key) Symmetric() bool {
	return true
}

func (k *sm4Key) Private() bool {
	return true
}

func (k *sm4Key) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key.")
}

type sm4EncKey struct {
	ski []byte
	key []byte
}

func (k *sm4EncKey) Bytes() (raw []byte, err error) {
	return k.key, nil
}

func (k *sm4EncKey) SKI() []byte {
	return k.ski
}

func (k *sm4EncKey) Symmetric() bool {
	return true
}

func (k *sm4EncKey) Private() bool {
	return true
}

func (k *sm4EncKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key.")
}
