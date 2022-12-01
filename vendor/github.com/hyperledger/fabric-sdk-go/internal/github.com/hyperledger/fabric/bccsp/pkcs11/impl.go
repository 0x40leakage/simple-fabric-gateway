/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package pkcs11

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
	gmPlugin "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	cpt "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
	"hash"
	"os"
	"strings"
	"sync"
)

var (
	logger                  = flogging.MustGetLogger("bccsp_p11")
	ctxMap                  = make(map[string]*pkcs11.Ctx)
	defaultSessionCacheSize = 4
)

// New WithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func New(opts PKCS11Opts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.SecLevel, opts.HashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration")
	}

	var bcCSP bccsp.BCCSP
	switch opts.Algorithm {
	case "GM":
		gmPlugin.InitGMPlugin("ccsgm")
		if bcCSP, err = gm.New(keyStore); err != nil {
			return nil, errors.Wrapf(err, "Failed initializing fallback GM BCCSP")
		}
	case "SW":
		if bcCSP, err = sw.NewWithParams(opts.SecLevel, opts.HashFamily, keyStore); err != nil {
			return nil, errors.Wrapf(err, "Failed initializing fallback SW BCCSP")
		}
	default:
		return nil, errors.New("Param Algorithm in BCCSP section of config file must only be GM or SW")
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.New("Invalid bccsp.KeyStore instance. It must be different from nil")
	}

	sessPool := make(chan pkcs11.SessionHandle, defaultSessionCacheSize)

	csp := &impl{
		BCCSP:       bcCSP,
		conf:        conf,
		softVerify:  opts.SoftVerify,
		immutable:   opts.Immutable,
		algorithm:   opts.Algorithm,
		secLevel:    opts.SecLevel,
		hashFamily:  opts.HashFamily,
		sessPool:    sessPool,
		sessions:    map[pkcs11.SessionHandle]struct{}{},
		handleCache: map[string]pkcs11.ObjectHandle{},
		keyCache:    map[string]bccsp.Key{},
		altId:       opts.AltId,
	}

	return csp.initialize(opts)
}

type impl struct {
	bccsp.BCCSP

	conf *config
	ks   bccsp.KeyStore

	ctx  *pkcs11.Ctx
	slot uint
	pin  string

	lib        string
	softVerify bool
	//Immutable flag makes object immutable
	immutable bool
	// GM or SW
	algorithm string
	// hash security level: 256 or 384
	secLevel int
	// hash family: SHA2 or SHA3
	hashFamily string

	// Alternate identifier of the private key
	altId string

	sessLock sync.Mutex
	sessPool chan pkcs11.SessionHandle
	sessions map[pkcs11.SessionHandle]struct{}

	cacheLock   sync.RWMutex
	handleCache map[string]pkcs11.ObjectHandle
	keyCache    map[string]bccsp.Key
}

// KeyGen generates a key using opts.
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	// Parse algorithm
	switch opts.(type) {
	case *bccsp.ECDSAKeyGenOpts:
		ski, pub, err := csp.generateECKey(csp.conf.ellipticCurve, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating ECDSA key")
		}
		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}

	case *bccsp.ECDSAP256KeyGenOpts:
		ski, pub, err := csp.generateECKey(oidNamedCurveP256, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating ECDSA P256 key")
		}

		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}

	case *bccsp.ECDSAP384KeyGenOpts:
		ski, pub, err := csp.generateECKey(oidNamedCurveP384, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating ECDSA P384 key")
		}

		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}

	case *bccsp.SM2KeyGenOpts:
		ski, pub, err := csp.generateSM2Key(oidNamedCurveP256SM2, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating SM2 P256 key")
		}

		k = &sm2PrivateKey{ski, sm2PublicKey{ski, pub}}

	case *bccsp.AESKeyGenOpts:
		_, privKey, err := csp.generateAESKey(csp.conf.aesByteLength, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating AES key")
		}

		k = &aesPrivateKey{privKey: privKey, exportable: false}

	case *bccsp.AES256KeyGenOpts:
		_, privKey, err := csp.generateAESKey(32, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating AES P256 key")
		}

		k = &aesPrivateKey{privKey: privKey, exportable: false}

	case *bccsp.AES192KeyGenOpts:
		_, privKey, err := csp.generateAESKey(24, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating AES P192 key")
		}

		k = &aesPrivateKey{privKey: privKey, exportable: false}

	case *bccsp.AES128KeyGenOpts:
		_, privKey, err := csp.generateAESKey(16, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating AES P128 key")
		}

		k = &aesPrivateKey{privKey: privKey, exportable: false}

	case *bccsp.SM4KeyGenOpts:
		ski, privKey, err := csp.generateSM4Key(opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating SM4 key")
		}

		k = &sm4PrivateKey{key: privKey, ski: ski}

	default:
		return csp.BCCSP.KeyGen(opts)
	}

	return k, nil
}

func (csp *impl) cacheKey(ski []byte, key bccsp.Key) {
	csp.cacheLock.Lock()
	csp.keyCache[hex.EncodeToString(ski)] = key
	csp.cacheLock.Unlock()
}

func (csp *impl) cachedKey(ski []byte) (bccsp.Key, bool) {
	csp.cacheLock.RLock()
	defer csp.cacheLock.RUnlock()
	key, ok := csp.keyCache[hex.EncodeToString(ski)]
	return key, ok
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil")
	}

	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	switch opts.(type) {

	case *bccsp.X509PublicKeyImportOpts:

		x509Cert, ok := raw.(*x509.Certificate)
		if !ok {
			return nil, errors.New("[X509PublicKeyImportOpts] Invalid raw material. Expected *x509.Certificate")
		}

		pk := x509Cert.PublicKey

		switch pk.(type) {
		case *sm2.PublicKey:
			return csp.KeyImport(pk, &bccsp.SM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
		case *ecdsa.PublicKey:
			if csp.algorithm == "GM" {
				return csp.KeyImport(pk, &bccsp.SM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
			}
			return csp.KeyImport(pk, &bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		default:
			return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA, SM2]")
		}

	case *bccsp.SM2PublicKeyImportOpts:
		var cptPk *cpt.PublicKey

		switch raw.(type) {
		case *ecdsa.PublicKey:
			cptPk = (*cpt.PublicKey)(raw.(*ecdsa.PublicKey))
		case *sm2.PublicKey:
			sm2Pk := raw.(*sm2.PublicKey)
			cptPk = &cpt.PublicKey{
				Curve: sm2Pk.Curve,
				X:     sm2Pk.X,
				Y:     sm2Pk.Y,
			}
		default:
			return nil, errors.New("[SM2PublicKeyImportOpts] Invalid raw material. Expected *ecdsa.PublicKey or *sm2.PublicKey.")
		}

		ski, err := csp.genSKIAsymKey(cptPk.Curve, cptPk.X, cptPk.Y, SM2)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to generate SM2 public key ski")
		}

		return &sm2PublicKey{ski: ski, pub: cptPk}, nil

	case *bccsp.ECDSAGoPublicKeyImportOpts:

		ecdsaPk, ok := raw.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("[ECDSAGoPublicKeyImportOpts] Invalid raw material. Expected *ecdsa.PublicKey.")
		}

		ski, err := csp.genSKIAsymKey(ecdsaPk.Curve, ecdsaPk.X, ecdsaPk.Y, EC)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to generate ECC public key ski")
		}

		return &ecdsaPublicKey{ski: ski, pub: ecdsaPk}, nil

	case *bccsp.AES256ImportKeyOpts:

		aesRaw, ok := raw.([]byte)
		if !ok {
			return nil, errors.New("Invalid raw material. Expected byte array.")
		} else if aesRaw == nil {
			return nil, errors.New("Invalid raw material. It must not be nil.")
		} else if len(aesRaw) != 32 {
			return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
		}

		return &aesPrivateKey{utils.Clone(aesRaw), false}, nil

	default:
		logger.Infof("key import not using PKCS11, KeyImportOpts:[%v]", opts)
		return csp.BCCSP.KeyImport(raw, opts)
	}
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *impl) GetKey(ski []byte) (bccsp.Key, error) {
	if key, ok := csp.cachedKey(ski); ok {
		return key, nil
	}

	key, err := csp.getKey(ski)
	if err != nil {
		logger.Debugf("Key not found using PKCS11: %v", err)
		return csp.BCCSP.GetKey(ski)
	}

	csp.cacheKey(ski, key)
	return key, nil
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty")
	}

	// Check key type
	switch k.(type) {
	case *ecdsaPrivateKey:
		return csp.signECDSA(*k.(*ecdsaPrivateKey), digest, opts)
	case *sm2PrivateKey:
		return csp.signSM2(*k.(*sm2PrivateKey), digest, opts)
	default:
		return csp.BCCSP.Sign(k, digest, opts)
	}
}

// Verify verifies signature against key k and digest
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (ok bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	// Check key type
	switch k.(type) {
	case *ecdsaPrivateKey:
		ok, err = csp.verifyECDSA(k.(*ecdsaPrivateKey).pub, signature, digest, opts)

		// 当 CKR_KEY_HANDLE_INVALID出现时, 加密机可能自动删除了刚刚 create 出来的 key object，因此这里再尝试使用 sw 软验签
		if err != nil && strings.Contains(err.Error(), "[pkcs11: 0x60: CKR_KEY_HANDLE_INVALID]") {
			swECDSAPublicKey := sw.ToECDSAPublicKey(k.(*ecdsaPrivateKey).pub.pub)
			ok, err = csp.BCCSP.Verify(swECDSAPublicKey, signature, digest, opts)
		}
	case *ecdsaPublicKey:
		ok, err = csp.verifyECDSA(*k.(*ecdsaPublicKey), signature, digest, opts)

		// 当 CKR_KEY_HANDLE_INVALID出现时, 加密机可能自动删除了刚刚 create 出来的 key object，因此这里再尝试使用 sw 软验签
		if err != nil && strings.Contains(err.Error(), "[pkcs11: 0x60: CKR_KEY_HANDLE_INVALID]") {
			swECDSAPublicKey := sw.ToECDSAPublicKey(k.(*ecdsaPublicKey).pub)
			ok, err = csp.BCCSP.Verify(swECDSAPublicKey, signature, digest, opts)
		}
	case *sm2PrivateKey:
		ok, err = csp.verifySM2(k.(*sm2PrivateKey).pub, signature, digest, opts)

		// 当 CKR_KEY_HANDLE_INVALID出现时, 加密机可能自动删除了刚刚 create 出来的 key object，因此这里再尝试使用 gm 软验签
		if err != nil && strings.Contains(err.Error(), "[pkcs11: 0x60: CKR_KEY_HANDLE_INVALID]") {
			gmSM2PublicKey := gm.ToSm2PublicKey(k.(*sm2PrivateKey).pub.pub, k.SKI())
			ok, err = csp.BCCSP.Verify(gmSM2PublicKey, signature, digest, opts)
		}
	case *sm2PublicKey:
		ok, err = csp.verifySM2(*k.(*sm2PublicKey), signature, digest, opts)

		// 当 CKR_KEY_HANDLE_INVALID出现时, 加密机可能自动删除了刚刚 create 出来的 key object，因此这里再尝试使用 gm 软验签
		if err != nil && strings.Contains(err.Error(), "[pkcs11: 0x60: CKR_KEY_HANDLE_INVALID]") {
			gmSM2PublicKey := gm.ToSm2PublicKey(k.(*sm2PublicKey).pub, k.SKI())
			ok, err = csp.BCCSP.Verify(gmSM2PublicKey, signature, digest, opts)
		}
	default:
		ok, err = csp.BCCSP.Verify(k, signature, digest, opts)
	}

	// the err info will be overrided, so we log it
	if err != nil {
		logger.Errorf("err occur when verifying signature [%s]", err)
	} else if !ok {
		logger.Debugf("Failed to verify signature")
	}

	return
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("Invalid plaintext. Cannot be empty")
	}

	// Check key type
	switch k.(type) {
	case *aesPrivateKey:
		return csp.encryptAES(*k.(*aesPrivateKey), plaintext, opts)
	case *sm4PrivateKey:
		return csp.encryptSM4(*k.(*sm4PrivateKey), plaintext, opts)
	case *sm2PublicKey:
		digest, err := csp.encryptSM2Key(k.SKI(), plaintext, k.(*sm2PublicKey).pub)
		if err == nil {
			return digest, nil
		} else if strings.Contains(err.Error(), "[pkcs11: 0x60: CKR_KEY_HANDLE_INVALID]") {

			// 当 CKR_KEY_HANDLE_INVALID出现时, 加密机可能自动删除了刚刚 create 出来的 key object，因此这里再尝试使用 gm 软加密
			gmSM2PublicKey := gm.ToSm2PublicKey(k.(*sm2PublicKey).pub, k.SKI())
			return csp.BCCSP.Encrypt(gmSM2PublicKey, plaintext, opts)
		}
		return digest, err
	}

	return csp.BCCSP.Encrypt(k, plaintext, opts)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil")
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("Invalid ciphertext. Cannot be empty")
	}

	// Check key type
	switch k.(type) {
	case *aesPrivateKey:
		return csp.decryptAES(*k.(*aesPrivateKey), ciphertext, opts)
	case *sm4PrivateKey:
		return csp.decryptSM4(*k.(*sm4PrivateKey), ciphertext, opts)
	case *sm2PrivateKey:
		return csp.decryptSM2key(k.SKI(), ciphertext)
	}

	return csp.BCCSP.Decrypt(k, ciphertext, opts)
}

func (csp *impl) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	if csp.algorithm == "GM" {
		return csp.hashPKCS11(msg, SM3)
	}

	// 1. 走BCCSP的hash配置
	var hashCfg bool
	if opts == nil {
		hashCfg = true
	} else if _, ok := opts.(*bccsp.SHAOpts); ok {
		hashCfg = true
	}
	if hashCfg {
		if csp.hashFamily == "SHA2" {
			switch csp.secLevel {
			case 256:
				return csp.hashPKCS11(msg, SHA256)
			case 384:
				return csp.hashPKCS11(msg, SHA384)
			default:
				return nil, errors.Errorf("SecLevel in BCCSP configuration must only be 256 or 384, not [%d]", csp.secLevel)
			}
		} else {
			return nil, errors.Errorf("HashFamily in BCCSP configuration must only be SHA2, not [%s]", csp.hashFamily)
		}
	}

	// 2. hashOpts
	switch opts.(type) {
	case *bccsp.SM3HashOpts:
		return csp.hashPKCS11(msg, SM3)
	case *bccsp.SHA256Opts:
		return csp.hashPKCS11(msg, SHA256)
	case *bccsp.SHA384Opts:
		return csp.hashPKCS11(msg, SHA384)
	//case *bccsp.SHA3_256Opts:
	//case *bccsp.SHA3_384Opts:
	default:
		return nil, errors.Errorf("Algorithm not recognized [%s]", opts.Algorithm())
	}
}

func (csp *impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	return nil, nil
}

// FindPKCS11Lib IS ONLY USED FOR TESTING
// This is a convenience function. Useful to self-configure, for tests where usual configuration is not
// available
func FindPKCS11Lib() (lib, pin, label string) {
	//FIXME: Till we workout the configuration piece, look for the libraries in the familiar places
	lib = os.Getenv("PKCS11_LIB")
	if lib == "" {
		pin = "98765432"
		label = "ForFabric"
		possibilities := []string{
			"/usr/lib/softhsm/libsofthsm2.so",                            //Debian
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",           //Ubuntu
			"/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so",            //Ubuntu
			"/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so",      //Power
			"/usr/local/Cellar/softhsm/2.1.0/lib/softhsm/libsofthsm2.so", //MacOS
		}
		for _, path := range possibilities {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				lib = path
				break
			}
		}
	} else {
		pin = os.Getenv("PKCS11_PIN")
		label = os.Getenv("PKCS11_LABEL")
	}
	return lib, pin, label
}
