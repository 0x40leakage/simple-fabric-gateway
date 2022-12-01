package sdf

import (
	"bytes"
	"crypto/aes"
	"errors"
	"math/big"

	gmPlugin "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdf"
)

func toSDFECCKey(pubKey *crypto.PublicKey) *sdf.ECCPublicKey {
	// 转换公钥
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	pub := sdf.ECCPublicKey{
		Bits: 256,
	}
	copy(pub.X[sdf.ECCref_MAX_LEN-len(xBytes):], xBytes)
	copy(pub.Y[sdf.ECCref_MAX_LEN-len(yBytes):], yBytes)
	return &pub
}

func toGOKey(pub *sdf.ECCPublicKey) *crypto.PublicKey {
	pubKey := new(crypto.PublicKey)
	pubKey.Curve = gmPlugin.NewSm2Curve().P256Sm2()
	pubKey.X = new(big.Int).SetBytes(pub.X[32:])
	pubKey.Y = new(big.Int).SetBytes(pub.Y[32:])
	return pubKey
}

func eccciphertoByte(cipher *sdf.ECCCipher) []byte {
	var ret []byte
	// C1
	ret = append(ret, cipher.X[32:]...)
	ret = append(ret, cipher.Y[32:]...)

	// C3
	ret = append(ret, cipher.M[:]...)

	// C2
	ret = append(ret, cipher.C[:cipher.L]...)
	return append([]byte{0x04}, ret...)
}

func byteToEcccipher(ciphertext []byte) *sdf.ECCCipher {
	var ret sdf.ECCCipher
	copy(ret.X[32:], ciphertext[1:33])
	copy(ret.Y[32:], ciphertext[33:65])
	copy(ret.M[:], ciphertext[65:97])

	ret.L = uint(len(ciphertext) - 97)
	copy(ret.C[:], ciphertext[97:])
	return &ret
}

func pkcs7Padding(src []byte) []byte {
	padding := SM4_BLOCKSIZE - len(src)%SM4_BLOCKSIZE
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}
