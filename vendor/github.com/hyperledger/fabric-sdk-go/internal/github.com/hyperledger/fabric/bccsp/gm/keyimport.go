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
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"unsafe"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	gminterface "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

var logger = flogging.MustGetLogger("gmkey")

type sm4KeyImporter struct {
	sm3 gminterface.Sm3
}

func (k *sm4KeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if sm4Raw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(sm4Raw) != 16 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 16 bytes", len(sm4Raw))
	}

	ski, err := k.sm3.Hash(sm4Raw)
	if err != nil {
		return nil, fmt.Errorf("Get ski error [%s]", err)
	}

	return &sm4PrivateKey{utils.Clone(sm4Raw), ski}, nil
}

type sm2PrivateKeyImporter struct {
	sm3 gminterface.Sm3
}

func (k *sm2PrivateKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[sm2PrivateKeyImporter] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[sm2PrivateKeyImporter] Invalid raw. It must not be nil.")
	}

	privKey, err := utils.DERToPrivateKey(der)
	if err != nil || privKey == nil {
		return nil, fmt.Errorf("Failed converting PKIX to sm2 private key [%s]", err)
	}

	sk, ok := privKey.(*crypto.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to sm2 private key. Invalid raw material.")
	}

	skraw := elliptic.Marshal(sk.Curve, sk.X, sk.Y)
	ski, err := k.sm3.Hash(skraw)
	if err != nil {
		return nil, fmt.Errorf("Get key ski error [%s]", err)
	}
	return &sm2PrivateKey{privKey: sk, ski: ski}, nil

}

type sm2PublicKeyImporter struct {
	sm3 gminterface.Sm3
}

func (k *sm2PublicKeyImporter) KeyImport(pk interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	var pub *crypto.PublicKey
	switch pk.(type) {
	case *sm2.PublicKey:
		pkk := pk.(*sm2.PublicKey)
		pub = &crypto.PublicKey{Curve: pkk.Curve, X: pkk.X, Y: pkk.Y}
	case *crypto.PublicKey:
		pub = pk.(*crypto.PublicKey)
	case *ecdsa.PublicKey:
		ecdsaPk := pk.(*ecdsa.PublicKey)
		pub = (*crypto.PublicKey)(unsafe.Pointer(ecdsaPk))
	}
	if pub != nil {
		raw := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		ski, err := k.sm3.Hash(raw)
		if err != nil {
			return nil, fmt.Errorf("KeyImport error, failed to get ski for [%s]", err)
		}
		return &sm2PublicKey{pubKey: pub, ski: ski}, nil
	}
	return nil, errors.New("Certificate's public key type not recognized. Supported keys: sm2")
}

type x509PublicKeyImporter struct {
	sm3 gminterface.Sm3
}

func (ki *x509PublicKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey
	importer := sm2PublicKeyImporter{ki.sm3}
	return importer.KeyImport(pk, opts)
}

type xinAnServerPublicKeyImporter struct{}

func (ki *xinAnServerPublicKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		logger.Errorf("invalid raw material. Expected *x509.Certificate.")
		return nil, errors.New("invalid raw material. Expected *x509.Certificate.")
	}
	return &xinAnPubKey{cert: x509Cert}, nil
}
