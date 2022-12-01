package ccsgm

import (
	"crypto/elliptic"
	"crypto/rand"
	stdX509 "crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	commoncrypto "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	commonX509 "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

var (
	oidNamedCurveSm2  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// struct to hold info required for PKCS#8
type pkcs8Info struct {
	Version int
	AlgorithmIdentifier
	PrivateKey []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// PrivateKeyToPEM converts the private key to PEM format.
// EC private keys are converted to PKCS#8 format.
// RSA private keys are converted to PKCS#1 format.
func PrivateKeyToPEM(privateKey *commoncrypto.PrivateKey, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return PrivateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	privateKeyBytes := privateKey.D.Bytes()
	paddedPrivateKey := make([]byte, (privateKey.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	// omit NamedCurveOID for compatibility as it's optional
	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oidNamedCurveSm2,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)},
	})

	if err != nil {
		return nil, fmt.Errorf("error marshaling SM2 key to asn1 [%s]", err)
	}
	var pkcs8Key pkcs8Info
	pkcs8Key.Version = 0
	var AlgorithmIdentifier AlgorithmIdentifier
	AlgorithmIdentifier.Algorithm = oidPublicKeyECDSA
	AlgorithmIdentifier.Parameters.Class = 0
	AlgorithmIdentifier.Parameters.Tag = 6
	AlgorithmIdentifier.Parameters.IsCompound = false
	AlgorithmIdentifier.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	pkcs8Key.AlgorithmIdentifier = AlgorithmIdentifier
	pkcs8Key.PrivateKey = asn1Bytes
	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		},
	), nil
}

// PrivateKeyToEncryptedPEM converts a private key to an encrypted PEM
func PrivateKeyToEncryptedPEM(priKey *commoncrypto.PrivateKey, pwd []byte) ([]byte, error) {
	if priKey == nil {
		return nil, errors.New("Invalid private key. It must be different from nil.")
	}

	oid := oidNamedCurveSm2
	privateKeyBytes := priKey.D.Bytes()
	paddedPrivateKey := make([]byte, (priKey.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(priKey.Curve, priKey.X, priKey.Y)},
	})
	if err != nil {
		return nil, err
	}

	var pkcs8Key pkcs8Info
	pkcs8Key.Version = 0
	var AlgorithmIdentifier AlgorithmIdentifier
	AlgorithmIdentifier.Algorithm = oidPublicKeyECDSA
	AlgorithmIdentifier.Parameters.Class = 0
	AlgorithmIdentifier.Parameters.Tag = 6
	AlgorithmIdentifier.Parameters.IsCompound = false
	AlgorithmIdentifier.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	pkcs8Key.AlgorithmIdentifier = AlgorithmIdentifier
	pkcs8Key.PrivateKey = asn1Bytes
	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)

	block, err := commonX509.EncryptPEMBlock(
		rand.Reader,
		"ENCRYPTED PRIVATE KEY",
		pkcs8Bytes,
		pwd,
		stdX509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// PEMtoPrivateKey unmarshal a pem to private key
func PEMtoPrivateKey(raw []byte, pwd []byte) (*commoncrypto.PrivateKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if commonX509.IsEncryptedPEMBlock(block) || block.Type == "ENCRYPTED PRIVATE KEY" {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}

		decrypted, err := commonX509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption [%s]", err)
		}

		key, err := commonX509.ParsePKCS8PrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		sm2Key, ok := key.(*commoncrypto.PrivateKey)
		if ok {
			return sm2Key, nil
		} else {
			return nil, errors.New("key type error")
		}
	}

	key, err := commonX509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	sm2Key, ok := key.(*commoncrypto.PrivateKey)
	if ok {
		return sm2Key, nil
	} else {
		return nil, errors.New("key type error")
	}
}

// PublicKeyToPEM marshals a public key to the pem format
func PublicKeyToPEM(publicKey *commoncrypto.PublicKey, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return PublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}

	PubASN1, err := commonX509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: PubASN1,
		},
	), nil

}

// PublicKeyToEncryptedPEM converts a public key to encrypted pem
func PublicKeyToEncryptedPEM(publicKey *commoncrypto.PublicKey, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return nil, errors.New("invalid password. It must be different from nil")
	}

	raw, err := commonX509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	block, err := commonX509.EncryptPEMBlock(
		rand.Reader,
		"PUBLIC KEY",
		raw,
		pwd,
		stdX509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

// PEMtoPublicKey unmarshal a pem to public key
func PEMtoPublicKey(raw []byte, pwd []byte) (*commoncrypto.PublicKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key
	if commonX509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different from nil")
		}

		decrypted, err := commonX509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption. [%s]", err)
		}

		key, err := commonX509.ParsePKIXPublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		sm2Pk, ok := key.(*commoncrypto.PublicKey)
		if ok {
			return sm2Pk, nil
		} else {
			return nil, errors.New("invalid public key format")
		}
	}

	key, err := commonX509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	sm2Pk, ok := key.(*commoncrypto.PublicKey)
	if ok {
		return sm2Pk, nil
	} else {
		return nil, errors.New("invalid public key format")
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func WriteKeyToPem(fileName string, key []byte, pwd []byte) (bool, error) {
	var block *pem.Block
	var err error

	if pwd != nil {
		if block, err = commonX509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, stdX509.PEMCipherAES256); err != nil {
			return false, err
		}
	} else {
		block = &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
	}

	file, err := os.Create(fileName)
	if err != nil {
		return false, err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func ReadKeyFromPem(fileName string, pwd []byte) ([]byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("SM4: pem decode failed")
	}

	if commonX509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if pwd == nil {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := commonX509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}

	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}

	return block.Bytes, nil
}
