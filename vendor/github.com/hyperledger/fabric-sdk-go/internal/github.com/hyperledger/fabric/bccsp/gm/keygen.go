/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	gminterface "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/xinan"
)

func getRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

type sm4KeyGenerator struct {
	sm3 gminterface.Sm3
}

func (kg *sm4KeyGenerator) KeyGen(_ bccsp.KeyGenOpts) (bccsp.Key, error) {
	key, err := getRandomBytes(SM4_KeyLen)
	if err != nil {
		return nil, fmt.Errorf("failed generating sm4 %d key [%s]", 16, err)
	}

	ski, err := kg.sm3.Hash(key)
	if err != nil {
		return nil, fmt.Errorf("failed generating sm4 ski [%s]", err)
	}
	return &sm4PrivateKey{key, ski}, nil

}

type xinanSm4KeyGenerator struct {
	sm3 gminterface.Sm3
	sm4 gminterface.Sm4
}

func (kg *xinanSm4KeyGenerator) KeyGen(_ bccsp.KeyGenOpts) (bccsp.Key, error) {
	if sm4, ok := kg.sm4.(*xinan.SM4); ok {
		key, err := sm4.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed generating sm4 %d key [%s]", 16, err)
		}
		ski, err := kg.sm3.Hash(key)
		if err != nil {
			return nil, fmt.Errorf("failed generating sm4 ski [%s]", err)
		}
		return &sm4PrivateKey{key: key, ski: ski}, nil
	}
	return nil, fmt.Errorf("should be xinan.SM4")
}

type sm2KeyGenerator struct {
	sm2 gminterface.Sm2
	sm3 gminterface.Sm3
}

func (kg *sm2KeyGenerator) KeyGen(bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	res, err := kg.sm2.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed generating sm2 key [%s]", err)
	}
	if res == nil {
		return nil, fmt.Errorf("failed generating sm2 key, res is nil")
	}

	key, ok := res.(*crypto.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed generating sm2 key, type is not *crypto.PrivateKey")
	}
	raw := elliptic.Marshal(key.Curve, key.X, key.Y)
	ski, err := kg.sm3.Hash(raw)
	if err != nil {
		return nil, fmt.Errorf("failed generating sm2 key ski [%s]", err)
	}
	return &sm2PrivateKey{key, ski}, nil
}

type xinan_sm2KeyGenerator struct {
	sm2 gminterface.Sm2
}

func (kg *xinan_sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	opt, ok := opts.(*bccsp.XinAnSM2KeyGenOpts)
	if !ok {
		return nil, fmt.Errorf("The opts is not for xinan")
	}
	key, err := kg.sm2.GenerateKey(opt.GetDN(), opt.GetAlias())
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm2 key [%s]", err)
	}
	if key == nil {
		return nil, fmt.Errorf("failed generating sm2 key")
	}
	if _, ok := key.([]byte); !ok {
		return nil, fmt.Errorf("failed generating sm2 key, key type must be []byte, but %T", key)
	}
	block, _ := pem.Decode(key.([]byte))
	if block == nil {
		return nil, fmt.Errorf("decode error")
	}
	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a csr")
	}
	dn, err := parseDN(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed generating sm2 key, csr parse failed %v", err)
	}
	k := xinAnPrivateKey{
		DN:  dn,
		csr: key.([]byte),
	}
	return &k, nil
}

type xinan_sm2KeyGenerator1 struct {
	sm2 gminterface.Sm2
}

// 仅作上传信安证书用，不返回实际key
func (kg *xinan_sm2KeyGenerator1) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	opt, ok := opts.(*bccsp.XinAnSM2KeyGenOpts1)
	if !ok {
		return nil, fmt.Errorf("The opts is not for xinan")
	}
	if sm2, ok := kg.sm2.(*xinan.SM2); ok {
		if err := sm2.ImportCert(opt.GetAlias(), opt.GetCert()); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return nil, fmt.Errorf("should be xinan.SM2")
}
