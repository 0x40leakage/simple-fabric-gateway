package sw

import (
	"crypto/rand"
	"errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/ccsgm"
)

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return ccsgm.NewSm2().Sign(k.(*sm2PrivateKey).privKey, rand.Reader, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	var err error
	verified := ccsgm.NewSm2().Verify(k.(*sm2PrivateKey).privKey.PublicKey, signature, digest)
	if !verified {
		err = errors.New("verify failed")
	}
	return verified, err
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	var err error
	verified := ccsgm.NewSm2().Verify(k.(*sm2PublicKey).pubKey, digest, signature)
	if !verified {
		err = errors.New("verify failed")
	}
	return verified, err
}
