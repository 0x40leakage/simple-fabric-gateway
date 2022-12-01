package pkcs11

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
)

func (csp *impl) signSM2(k sm2PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	r, s, err := csp.signP11SM2(k.ski, digest)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func (csp *impl) verifySM2(k sm2PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	return csp.verifyP11SM2(k.SKI(), digest, r, s, k.pub.Curve.Params().BitSize/8, k.pub.Curve, k.pub.X, k.pub.Y)
}

// 暂时只使用 SM2, 不使用 RSA
func (csp *impl) encryptSM2(k sm2PublicKey, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	// 1. encrypt using tian-an library
	var DERCipherText []byte
	if DERCipherText, err = csp.encryptSM2Key(k.SKI(), plaintext, k.pub); err != nil {
		return
	}

	// 2. DER decode
	ac := &AsymmetricCipher{}
	if _, err = asn1.Unmarshal(DERCipherText, ac); err != nil {
		return nil, fmt.Errorf("Failed asn1 unmashalling DER-decoded CipherText [%s]", err)
	}

	length := len(ac.X.Bytes()) + len(ac.Y.Bytes()) + len(ac.M) + len(ac.C)
	ciphertext = make([]byte, 0, 1+length)

	ciphertext = append(ciphertext, byte(0x04))
	ciphertext = append(ciphertext, ac.X.Bytes()...)
	ciphertext = append(ciphertext, ac.Y.Bytes()...)
	ciphertext = append(ciphertext, ac.M...) // hash
	ciphertext = append(ciphertext, ac.C...) // true cipher text

	return
}

// 暂时只使用 天安的库的SM2, 不使用 RSA
func (csp *impl) decryptSM2(k sm2PrivateKey, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// 1. DER encode
	ciphertext = ciphertext[1:] // drop 0x04
	ac := AsymmetricCipher{
		X: new(big.Int).SetBytes(ciphertext[:32]),
		Y: new(big.Int).SetBytes(ciphertext[32:64]),
		M: ciphertext[64:96],
		C: ciphertext[96:],
	}

	var DERCipherText []byte
	if DERCipherText, err = asn1.Marshal(ac); err != nil {
		return nil, fmt.Errorf("Failed to asn1-mashal into DER-encoded CipherText [%s]", err)
	}

	// 2. decrypt using tian-an library
	if plaintext, err = csp.decryptSM2key(k.SKI(), DERCipherText); err != nil {
		return
	}

	return
}
