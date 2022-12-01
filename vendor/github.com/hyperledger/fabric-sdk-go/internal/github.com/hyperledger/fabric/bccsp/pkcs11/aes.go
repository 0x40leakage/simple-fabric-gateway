package pkcs11

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

// AES 暂时只支持 CBC模式
func (csp *impl) encryptAES(k aesPrivateKey, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	switch o := opts.(type) {
	case *bccsp.AESCBCPKCS7ModeOpts:
		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return AESCBCPKCS7EncryptWithIV(csp, o.IV, k, plaintext)
		}

		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Encrypt(csp, k, plaintext)
	case bccsp.AESCBCPKCS7ModeOpts:
		return csp.encryptAES(k, plaintext, &o)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

// AES 暂时只支持 CBC模式
func (csp *impl) decryptAES(k aesPrivateKey, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// check for mode
	switch opts.(type) {
	case *bccsp.AESCBCPKCS7ModeOpts, bccsp.AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Decrypt(csp, k, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding, the IV used is the one passed to the function
func AESCBCPKCS7EncryptWithIV(csp *impl, IV []byte, k aesPrivateKey, src []byte) ([]byte, error) {
	// 1. padding
	tmp := pkcs7Padding(src)

	return cbcPKCS7EncryptWithIV(csp, IV, &k, tmp)
}

func AESCBCPKCS7Encrypt(csp *impl, k aesPrivateKey, src []byte) ([]byte, error) {
	// 1. padding
	tmp := pkcs7Padding(src)

	return cbcEncryptWithRand(csp, &k, tmp)
}

func AESCBCPKCS7Decrypt(csp *impl, k aesPrivateKey, ciphertext []byte) ([]byte, error) {
	// First decrypt
	pt, err := cbcDecrypt(csp, &k, ciphertext)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}
