package ccsgm

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/Hyperledger-TWGC/ccs-gm/sm4"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"io"
)

type SM4 struct {
}

func NewSm4() gm.Sm4 {
	return &SM4{}
}

func (s *SM4) Encrypt(key []byte, plaintext []byte, _ ...interface{}) ([]byte, error) {
	return sm4CBCPKCS7Encrypt(key, plaintext)
}

func (s *SM4) Decrypt(key []byte, ciphertext []byte, _ ...interface{}) ([]byte, error) {
	return sm4CBCPKCS7Decrypt(key, ciphertext)
}

// Sm4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func sm4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncrypt(key, tmp)
}

func pkcs7Padding(src []byte) []byte {
	padding := sm4.BlockSize - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	iv := make([]byte, sm4.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return sm4CBCEncryptWithIV(iv, key, s)
}

func sm4CBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("invalid plaintext. It must be a multiple of the block size")
	}

	if len(IV) != sm4.BlockSize {
		return nil, errors.New("invalid IV. It must have length the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize], IV)

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:], s)

	return ciphertext, nil
}

// Sm4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func sm4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := sm4CBCDecrypt(key, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("invalid pkcs7 padding (unpadding > sm4.sm4.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < sm4.BlockSize {
		return nil, errors.New("invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

func SaveKeyToPem(fileName string, key []byte, pwd []byte) (bool, error) {
	return WriteKeyToPem(fileName, key, pwd)
}

func LoadKeyFromPem(fileName string, pwd []byte) ([]byte, error) {
	return ReadKeyFromPem(fileName, pwd)
}
