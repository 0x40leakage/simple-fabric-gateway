/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	gminterface "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/ccsgm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if aesRaw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := derToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return &ecdsaPrivateKey{ecdsaSK, true}, nil
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey

	switch pk := pk.(type) {
	case *ecdsa.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *rsa.PublicKey:
		// This path only exists to support environments that use RSA certificate
		// authorities to issue ECDSA certificates.
		return &rsaPublicKey{pubKey: pk}, nil
	case *sm2.PublicKey:
		pub := &crypto.PublicKey{Curve: pk.Curve, X: pk.X, Y: pk.Y}
		raw := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
		ski, err := ccsgm.NewSm3().Hash(raw)
		if err != nil {
			return nil, fmt.Errorf("KeyImport error, failed to get ski for [%s]", err)
		}
		return &sm2PublicKey{pubKey: pub, ski: ski}, nil
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	}
}

type sm4KeyImportOptsKeyImporter struct {
	sm3 gminterface.Sm3
}

func (k *sm4KeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
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

type sm2PrivateKeyImportOptsKeyImporter struct {
	sm3 gminterface.Sm3
}

func (k *sm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
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

type sm2PublicKeyImportOptsKeyImporter struct {
	sm3 gminterface.Sm3
}

func (k *sm2PublicKeyImportOptsKeyImporter) KeyImport(pk interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
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

type x509SM2PublicKeyImportOptsKeyImporter struct {
	sm3 gminterface.Sm3
}

func (ki *x509SM2PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}
	pk := x509Cert.PublicKey
	importer := sm2PublicKeyImportOptsKeyImporter{ki.sm3}
	return importer.KeyImport(pk, opts)
}
