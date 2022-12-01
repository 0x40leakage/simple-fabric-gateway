/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"hash"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

//NewCryptoSuite returns cryptosuite adaptor for given bccsp.BCCSP implementation
func NewCryptoSuite(bccsp bccsp.BCCSP) core.CryptoSuite {
	return &CryptoSuite{
		BCCSP: bccsp,
	}
}

//GetKey returns implementation of of cryptosuite.Key
func GetKey(newkey bccsp.Key) core.Key {
	return &key{newkey}
}

//GetKey returns implementation of of cryptosuite.Key
func GetBCCSPKey(newkey core.Key) bccsp.Key {
	return &BCCSPKey{newkey}
}

// CryptoSuite provides a wrapper of BCCSP
type CryptoSuite struct {
	BCCSP bccsp.BCCSP
}

// KeyGen is a wrapper of BCCSP.KeyGen
func (c *CryptoSuite) KeyGen(opts core.KeyGenOpts) (k core.Key, err error) {
	key, err := c.BCCSP.KeyGen(opts)
	return GetKey(key), err
}

// KeyImport is a wrapper of BCCSP.KeyImport
func (c *CryptoSuite) KeyImport(raw interface{}, opts core.KeyImportOpts) (k core.Key, err error) {
	key, err := c.BCCSP.KeyImport(raw, opts)
	return GetKey(key), err
}

// GetKey is a wrapper of BCCSP.GetKey
func (c *CryptoSuite) GetKey(ski []byte) (k core.Key, err error) {
	key, err := c.BCCSP.GetKey(ski)
	return GetKey(key), err
}

// Hash is a wrapper of BCCSP.Hash
func (c *CryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
	return c.BCCSP.Hash(msg, opts)
}

// GetHash is a wrapper of BCCSP.GetHash
func (c *CryptoSuite) GetHash(opts core.HashOpts) (h hash.Hash, err error) {
	return c.BCCSP.GetHash(opts)
}

// Sign is a wrapper of BCCSP.Sign
func (c *CryptoSuite) Sign(k core.Key, digest []byte, opts core.SignerOpts) (signature []byte, err error) {
	return c.BCCSP.Sign(k.(*key).key, digest, opts)
}

// Verify is a wrapper of BCCSP.Verify
func (c *CryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	return c.BCCSP.Verify(k.(*key).key, signature, digest, opts)
}

// Encrypt is a wrapper of BCCSP.Encrypt
func (c *CryptoSuite) Encrypt(k core.Key, plaintext []byte, opts core.EncrypterOpts) (ciphertext []byte, err error) {
	return c.BCCSP.Encrypt(k.(*key).key, plaintext, opts)
}

// Decrypt is a wrapper of BCCSP.Decrypt
func (c *CryptoSuite) Decrypt(k core.Key, ciphertext []byte, opts core.DecrypterOpts) (plaintext []byte, err error) {
	return c.BCCSP.Decrypt(k.(*key).key, ciphertext, opts)
}

type key struct {
	key bccsp.Key
}

func (k *key) Bytes() ([]byte, error) {
	return k.key.Bytes()
}

func (k *key) SKI() []byte {
	return k.key.SKI()
}

func (k *key) Symmetric() bool {
	return k.key.Symmetric()
}

func (k *key) Private() bool {
	return k.key.Private()
}

func (k *key) PublicKey() (core.Key, error) {
	key, err := k.key.PublicKey()
	return GetKey(key), err
}

type BCCSPKey struct {
	key core.Key
}

func (k *BCCSPKey) Bytes() ([]byte, error) {
	return k.key.Bytes()
}

func (k *BCCSPKey) SKI() []byte {
	return k.key.SKI()
}

func (k *BCCSPKey) Symmetric() bool {
	return k.key.Symmetric()
}

func (k *BCCSPKey) Private() bool {
	return k.key.Private()
}

func (k *BCCSPKey) PublicKey() (bccsp.Key, error) {
	key, err := k.key.PublicKey()
	return GetBCCSPKey(key), err
}

// Bccsp provides a wrapper of CryptoSuite
type BCCSP struct {
	CryptoSuite core.CryptoSuite
}

// ToDo
func (c *BCCSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	return nil, nil
}

// ToDo
func (c *BCCSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	return nil, nil
}

// ToDo
func (c *BCCSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	return nil, nil
}

//NewBCCSP returns cryptosuite adaptor for given bccsp.BCCSP implementation
func NewBCCSP(c core.CryptoSuite) bccsp.BCCSP {
	return &BCCSP{
		CryptoSuite: c,
	}
}

// KeyGen is a wrapper of BCCSP.KeyGen
func (c *BCCSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	key, err := c.CryptoSuite.KeyGen(opts)
	return GetBCCSPKey(key), err
}

// KeyImport is a wrapper of BCCSP.KeyImport
func (c *BCCSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	key, err := c.CryptoSuite.KeyImport(raw, opts)
	return GetBCCSPKey(key), err
}

// GetKey is a wrapper of BCCSP.GetKey
func (c *BCCSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	key, err := c.CryptoSuite.GetKey(ski)
	return GetBCCSPKey(key), err
}

// Hash is a wrapper of BCCSP.Hash
func (c *BCCSP) Hash(msg []byte, opts bccsp.HashOpts) (hash []byte, err error) {
	return c.CryptoSuite.Hash(msg, opts)
}

// GetHash is a wrapper of BCCSP.GetHash
func (c *BCCSP) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	return c.CryptoSuite.GetHash(opts)
}

// Sign is a wrapper of BCCSP.Sign
func (c *BCCSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return c.CryptoSuite.Sign(k.(*BCCSPKey).key, digest, opts)
}

// Verify is a wrapper of BCCSP.Verify
func (c *BCCSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return c.CryptoSuite.Verify(k.(*BCCSPKey).key, signature, digest, opts)
}

//// Verify is a wrapper of BCCSP.Verify
//func (c *BCCSP) Decrypt(k bccsp.Key, ciphertext []byte, opts core.) (plaintext []byte, err error) {
//	return c.CryptoSuite.Verify(k.(*BCCSPKey).key, signature, digest, opts)
//}
