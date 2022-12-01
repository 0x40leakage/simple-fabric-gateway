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
	"crypto/rand"
	"fmt"
	"hash"
	"reflect"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	gminterface "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/pkg/errors"
)

const SM4_KeyLen = 16

type impl struct {
	ks            bccsp.KeyStore
	implType      string
	keyGenerators map[reflect.Type]KeyGenerator
	keyImporters  map[reflect.Type]KeyImporter
	sm2           gminterface.Sm2
	sm3           gminterface.Sm3
	sm4           gminterface.Sm4
}

func New(keyStore bccsp.KeyStore, library ...string) (bccsp.BCCSP, error) {
	if len(library) == 0 {
		library = append(library, "")
	}
	if keyStore == nil {
		return nil, errors.Errorf("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}
	impl := &impl{ks: keyStore, implType: library[0]}
	impl.sm2 = gm.NewSm2()
	impl.sm3 = gm.NewSm3()
	impl.sm4 = gm.NewSm4()

	keyImporters := make(map[reflect.Type]KeyImporter)
	keyGenerators := make(map[reflect.Type]KeyGenerator)

	keyImporters[reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{})] = &sm2PrivateKeyImporter{impl.sm3}
	keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})] = &sm2PublicKeyImporter{impl.sm3}
	keyImporters[reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{})] = &sm2PublicKeyImporter{impl.sm3}
	keyImporters[reflect.TypeOf(&bccsp.SM4KeyImportOpts{})] = &sm4KeyImporter{impl.sm3}

	if library[0] == "xin_an" {
		keyImporters[reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{})] = &xinAnServerPublicKeyImporter{}
		keyGenerators[reflect.TypeOf(&bccsp.SM4KeyGenOpts{})] = &xinanSm4KeyGenerator{impl.sm3, impl.sm4}
	} else {
		// ccsgm
		keyImporters[reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{})] = &x509PublicKeyImporter{impl.sm3}
		keyGenerators[reflect.TypeOf(&bccsp.SM4KeyGenOpts{})] = &sm4KeyGenerator{impl.sm3}
	}

	// todo 待加密机二开支持sm2产生公私钥，需要根据library区别对待
	keyGenerators[reflect.TypeOf(&bccsp.SM2KeyGenOpts{})] = &sm2KeyGenerator{impl.sm2, impl.sm3}
	keyGenerators[reflect.TypeOf(&bccsp.XinAnSM2KeyGenOpts{})] = &xinan_sm2KeyGenerator{impl.sm2}
	keyGenerators[reflect.TypeOf(&bccsp.XinAnSM2KeyGenOpts1{})] = &xinan_sm2KeyGenerator1{impl.sm2}
	keyGenerators[reflect.TypeOf(&bccsp.ECDSAP256KeyGenOpts{})] = &sm2KeyGenerator{impl.sm2, impl.sm3}

	impl.keyGenerators = keyGenerators
	impl.keyImporters = keyImporters

	return impl, nil
}

// KeyGen generates a key using opts.
func (gmcsp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	keyGenerator, found := gmcsp.keyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed generating key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = gmcsp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}
	return k, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	return nil, nil
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyImporter, found := gmcsp.keyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyImportOpts' provided [%v]", opts)
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = gmcsp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing imported key with opts [%v]", opts)
		}
	}

	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (gmcsp *impl) GetKey(ski []byte) (bccsp.Key, error) {
	if gmcsp.implType == "xin_an" {

		cert, err := x509.ParseCertificate(ski)
		if err != nil {
			return nil, errors.Wrapf(err, "GetKey error")
		}
		xinAnPubKey := xinAnPubKey{}
		xinAnPubKey.cert = cert
		priv := &xinAnPrivateKey{xinAnPubKey, cert.Subject.String(), nil}
		// 签名确认私钥是否存在
		if _, err = gmcsp.Sign(priv, []byte("test"), nil); err != nil {
			return nil, errors.New("Key not exists on xinan server")
		}
		return priv, nil
	} else if gmcsp.implType == "ccsgm" {
		return gmcsp.ks.GetKey(ski)
	}
	return nil, fmt.Errorf("not support impType for %s", gmcsp.implType)
}

// Hash hashes messages msg using options opts.
func (gmcsp *impl) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	return gmcsp.sm3.Hash(msg)
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (gmcsp *impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	return nil, nil
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (gmcsp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	switch k.(type) {
	case *sm2PrivateKey:
		sk := k.(*sm2PrivateKey)
		if sk.privKey == nil {
			return nil, errors.New("Invalid sm2PrivateKey Key. It's privKey must not be nil.")
		}
		signature, err = gmcsp.sm2.Sign(sk.privKey, rand.Reader, digest, opts)
	case *xinAnPrivateKey:
		sk := k.(*xinAnPrivateKey)
		if sk.DN == "" {
			return nil, errors.New("Invalid xinAnPrivateKey Key. It's dn must not be empty.")
		}
		signature, err = gmcsp.sm2.Sign(sk.DN, rand.Reader, digest, opts)
	default:
		return nil, errors.New("Invalid private Key")
	}
	return
}

// Verify verifies signature against key k and digest
func (gmcsp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	switch k.(type) {
	case *sm2PublicKey:
		pk := k.(*sm2PublicKey)
		if pk.pubKey == nil {
			return false, errors.New("Invalid sm2PublicKey Key. It's pubKey must not be nil.")
		}
		valid = gmcsp.sm2.Verify(pk.pubKey, digest, signature)
	case *xinAnPubKey:
		valid = gmcsp.sm2.Verify(k.SKI(), digest, signature)
	default:
		return false, errors.New("Invalid public Key.")
	}
	return
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	switch k.(type) {
	case *sm2PublicKey:
		kk := k.(*sm2PublicKey)
		if kk.pubKey == nil {
			return nil, errors.New("Invalid sm2PublicKey Key. It's pubKey must not be nil.")
		}
		return gmcsp.sm2.Encrypt(kk.pubKey, plaintext)
	case *xinAnPubKey:
		return gmcsp.sm2.Encrypt(k.SKI(), plaintext)
	case *sm4PrivateKey:
		kk := k.(*sm4PrivateKey)
		if kk.key == nil {
			return nil, errors.New("Invalid sm4PrivateKey Key. It's key must not be nil.")
		}
		return gmcsp.sm4.Encrypt(kk.key, plaintext)
	}
	return nil, errors.New("Invalid Key. It must be sm2PublicKey or sm4PrivateKey")
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	switch k.(type) {
	case *sm2PrivateKey:
		kk := k.(*sm2PrivateKey)
		if kk.privKey == nil {
			return nil, errors.New("Invalid sm2PrivateKey Key. It's privKey must not be nil.")
		}
		return gmcsp.sm2.Decrypt(kk.privKey, ciphertext)
	case *xinAnPrivateKey:
		sk := k.(*xinAnPrivateKey)
		if sk.DN == "" {
			return nil, errors.New("Invalid xinAnPrivateKey Key. It's dn must not be empty.")
		}
		return gmcsp.sm2.Decrypt(sk.DN, ciphertext)
	case *sm4PrivateKey:
		kk := k.(*sm4PrivateKey)
		if kk.key == nil {
			return nil, errors.New("Invalid sm4PrivateKey Key. It's key must not be nil.")
		}
		return gmcsp.sm4.Decrypt(kk.key, ciphertext)
	}
	return nil, errors.New("Invalid Key. It must be sm2PrivateKey or sm4PrivateKey")
}
