/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	gocrypto "crypto"
	"crypto/elliptic"
	"io"
)

type Sm2 interface {
	// 创建私钥
	GenerateKey(opts ...interface{}) (interface{}, error)

	// 数字签名和验证
	Sign(priv interface{}, rand io.Reader, digest []byte, opts gocrypto.SignerOpts) ([]byte, error)
	Verify(pub interface{}, digest []byte, sign []byte) bool

	// 非对称加密和解密
	Encrypt(pub interface{}, plaintext []byte) ([]byte, error)
	Decrypt(priv interface{}, ciphertext []byte) ([]byte, error)
}

type Sm3 interface {
	Hash(msg []byte) ([]byte, error)
}

type Sm4 interface {
	Encrypt(key []byte, plaintext []byte, opts ...interface{}) ([]byte, error)
	Decrypt(key []byte, ciphertext []byte, opts ...interface{}) ([]byte, error)
}

type Sm2Curve interface {
	P256Sm2() elliptic.Curve
}
