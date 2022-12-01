package gm

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
)

func ToSm2PublicKey(pubKey *crypto.PublicKey, ski []byte) *sm2PublicKey {
	return &sm2PublicKey{pubKey: pubKey, ski: ski}
}
