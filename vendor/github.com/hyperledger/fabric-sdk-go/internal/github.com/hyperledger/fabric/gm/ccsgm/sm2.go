package ccsgm

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	commoncrypto "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
)

type SM2 struct{}

func NewSm2() gm.Sm2 {
	return &SM2{}
}

const (
	PublicKeyError  = "pub must be *crypto.PublicKey"
	PrivateKeyError = "priv must be *crypto.PrivateKey"
)

func (s *SM2) GenerateKey(_ ...interface{}) (interface{}, error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		logger.Errorf("failed to generate private, err: %v", err)
		return nil, err
	}
	return toCryptoPrivateKey(key), nil
}

func (s *SM2) Sign(priv interface{}, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if p, ok := priv.(*commoncrypto.PrivateKey); ok {
		privKey := toSm2PrivateKey(p)
		return privKey.Sign(rand, digest, opts)
	}
	logger.Errorf(PrivateKeyError)
	return nil, errors.New(PrivateKeyError)
}

func (s *SM2) Verify(pub interface{}, digest []byte, sign []byte) bool {
	if p, ok := pub.(*commoncrypto.PublicKey); ok {
		pubKey := toSm2PublicKey(p)
		return pubKey.Verify(digest, sign)
	}
	logger.Errorf(PublicKeyError)
	return false
}

func (s *SM2) Encrypt(pub interface{}, msg []byte) ([]byte, error) {
	if p, ok := pub.(*commoncrypto.PublicKey); ok {
		pubKey := toSm2PublicKey(p)
		return sm2.Encrypt(rand.Reader, pubKey, msg)
	}
	logger.Errorf(PublicKeyError)
	return nil, errors.New(PublicKeyError)
}

func (s *SM2) Decrypt(priv interface{}, ciphertext []byte) ([]byte, error) {
	if p, ok := priv.(*commoncrypto.PrivateKey); ok {
		privKey := toSm2PrivateKey(p)
		return sm2.Decrypt(privKey, ciphertext)
	}
	logger.Errorf(PrivateKeyError)
	return nil, errors.New(PrivateKeyError)
}

func SavePrivateKeytoPem(fileName string, key *commoncrypto.PrivateKey, pwd []byte) (bool, error) {
	pemBytes, err := PrivateKeyToPEM(key, pwd)
	if err != nil {
		logger.Errorf("failed to parse private key to PEM format: %s", err)
		return false, err
	}

	file, err := os.Create(fileName)
	if err != nil {
		return false, err
	}
	defer file.Close()

	_, err = file.Write(pemBytes)
	if err != nil {
		return false, err
	}

	return true, nil
}

func LoadPrivateKeyFromPem(fileName string, pwd []byte) (privKey *commoncrypto.PrivateKey, err error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	privKey, err = PEMtoPrivateKey(data, pwd)
	if err != nil {
		logger.Errorf("failed to unmarshal PEM to private key: %s", err)
		return nil, err
	}

	return
}

func SavePublicKeytoPem(fileName string, key *commoncrypto.PublicKey, _ []byte) (bool, error) {
	pemBytes, err := PublicKeyToPEM(key, nil)
	if err != nil {
		logger.Errorf("failed to parse public key to PEM format: %s", err)
		return false, err
	}

	file, err := os.Create(fileName)
	if err != nil {
		return false, err
	}
	defer file.Close()

	_, err = file.Write(pemBytes)
	if err != nil {
		return false, err
	}

	return true, nil
}

func LoadPublicKeyFromPem(fileName string, pwd []byte) (pubKey *commoncrypto.PublicKey, err error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	pubKey, err = PEMtoPublicKey(data, pwd)
	if err != nil {
		logger.Errorf("failed to unmarshal PEM to public key: %s", err)
		return nil, err
	}

	return
}
