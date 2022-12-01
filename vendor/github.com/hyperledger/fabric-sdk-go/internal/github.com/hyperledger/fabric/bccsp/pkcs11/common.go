package pkcs11

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/miekg/pkcs11"
)

type AsymmetricCipher struct {
	X *big.Int
	Y *big.Int
	M []byte
	C []byte
}

type symEncryptMode struct {
	symEncryptMechanism uint
	x                   []byte
}

// The block size in bytes.
const BlockSize = 16

func pkcs7Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > BlockSize || unpadding == 0 {
		return nil, errors.New("invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

// support AES and SM4
func cbcPKCS7EncryptWithIV(csp *impl, IV []byte, k bccsp.Key, src []byte) (ciphertext []byte, err error) {
	// 1. validate param
	if len(src)%BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	if len(IV) != BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	// 2. then encrypt using pkcs11 library
	var mode symEncryptMode
	switch k.(type) {
	case *aesPrivateKey:
		mode = symEncryptMode{symEncryptMechanism: pkcs11.CKM_AES_CBC, x: IV}
	case *sm4PrivateKey:
		mode = symEncryptMode{symEncryptMechanism: CKM_SM4_CBC, x: IV}
	}

	if ciphertext, err = csp.encryptSymmetric(k.SKI(), src, mode, false); err != nil {
		return nil, err
	}

	return
}

// support AES and SM4
func cbcEncryptWithRand(csp *impl, k bccsp.Key, src []byte) (ciphertext []byte, err error) {
	// 1. validate param
	if len(src)%BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	// 2. then encrypt using pkcs11 library
	var mode symEncryptMode
	switch k.(type) {
	case *aesPrivateKey:
		mode = symEncryptMode{symEncryptMechanism: pkcs11.CKM_AES_CBC, x: nil}
	case *sm4PrivateKey:
		mode = symEncryptMode{symEncryptMechanism: CKM_SM4_CBC, x: nil}
	}

	if ciphertext, err = csp.encryptSymmetric(k.SKI(), src, mode, true); err != nil {
		return nil, err
	}

	return
}

// support AES and SM4
func cbcDecrypt(csp *impl, k bccsp.Key, ciphertext []byte) ([]byte, error) {
	// 1. validate param
	if len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	// 2. separate iv and real-ciphertext
	iv := ciphertext[:BlockSize]
	src := ciphertext[BlockSize:]

	// 3. decrypt using pkcs11
	var mode symEncryptMode
	switch k.(type) {
	case *aesPrivateKey:
		mode = symEncryptMode{symEncryptMechanism: pkcs11.CKM_AES_CBC, x: iv}
	case *sm4PrivateKey:
		mode = symEncryptMode{symEncryptMechanism: CKM_SM4_CBC, x: iv}
	}

	return csp.decryptSymmetric(k.SKI(), src, mode)
}
