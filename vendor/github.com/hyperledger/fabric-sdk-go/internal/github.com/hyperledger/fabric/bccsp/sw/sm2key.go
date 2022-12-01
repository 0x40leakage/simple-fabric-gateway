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
package sw

import (
	"crypto/elliptic"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

type sm2PrivateKey struct {
	privKey *crypto.PrivateKey
	ski     []byte
}

func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return x509.MarshalECPrivateKey(k.privKey)
}

func (k *sm2PrivateKey) SKI() []byte {
	if len(k.ski) > 0 {
		return k.ski
	}

	// hash it
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	var err error
	k.ski, err = gm.NewSm3().Hash(raw)
	if err != nil {
		return nil
	}
	return k.ski
}

func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

func (k *sm2PrivateKey) Private() bool {
	return true
}

func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &sm2PublicKey{pubKey: &k.privKey.PublicKey, ski: k.ski}, nil
}

type sm2PublicKey struct {
	pubKey *crypto.PublicKey
	ski    []byte
}

func (k *sm2PublicKey) Bytes() ([]byte, error) {
	raw, err := x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%s]", err)
	}
	return raw, nil
}

func (k *sm2PublicKey) SKI() []byte {
	if len(k.ski) > 0 {
		return k.ski
	}

	// hash it
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	var err error
	k.ski, err = gm.NewSm3().Hash(raw)
	if err != nil {
		return nil
	}
	return k.ski
}

func (k *sm2PublicKey) Symmetric() bool {
	return false
}

func (k *sm2PublicKey) Private() bool {
	return false
}

func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
