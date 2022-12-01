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
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	gminterface "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
)

const SM4_KEY_LENGTH = 16

type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

func (kg *ecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating ECDSA key for [%v]: [%s]", kg.curve, err)
	}

	return &ecdsaPrivateKey{privKey, true}, nil
}

type aesKeyGenerator struct {
	length int
}

func (kg *aesKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", kg.length, err)
	}

	return &aesPrivateKey{lowLevelKey, false}, nil
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

type sm4KeyGenerator struct {
	sm3 gminterface.Sm3
}

func (kg *sm4KeyGenerator) KeyGen(_ bccsp.KeyGenOpts) (bccsp.Key, error) {
	key, err := getRandomBytes(SM4_KEY_LENGTH)
	if err != nil {
		return nil, fmt.Errorf("failed generating sm4 %d key [%s]", 16, err)
	}

	ski, err := kg.sm3.Hash(key)
	if err != nil {
		return nil, fmt.Errorf("failed generating sm4 ski [%s]", err)
	}

	return &sm4PrivateKey{key, ski}, nil
}
func getRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
