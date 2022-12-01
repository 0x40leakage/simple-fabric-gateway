package pkcs11

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

// SM4 暂时只支持 CBC模式
func (csp *impl) encryptSM4(k sm4PrivateKey, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	return sm4CBCPKCS7Encrypt(csp, k, plaintext)
}

// SM4 暂时只支持 CBC模式
func (csp *impl) decryptSM4(k sm4PrivateKey, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	return sm4CBCPKCS7Decrypt(csp, k, ciphertext)
}

func sm4CBCPKCS7Encrypt(csp *impl, k sm4PrivateKey, src []byte) ([]byte, error) {
	// 1. padding
	tmp := pkcs7Padding(src)

	return cbcEncryptWithRand(csp, &k, tmp)
}

func sm4CBCPKCS7Decrypt(csp *impl, k sm4PrivateKey, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := cbcDecrypt(csp, &k, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}
