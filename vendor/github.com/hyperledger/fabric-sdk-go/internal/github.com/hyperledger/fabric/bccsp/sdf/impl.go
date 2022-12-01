package sdf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"hash"
	"sync"
	"unsafe"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	gmPlugin "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdf"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
	"github.com/pkg/errors"
)

const (
	SM4_IPK_INDEX = 1
	SM4_KEYLEN    = 16
	SM4_BLOCKSIZE = 16
)

var (
	logger                  = flogging.MustGetLogger("bccsp_sdf")
	ctxMap                  = make(map[string]*sdf.Ctx)
	defaultSessionCacheSize = 4
)

type impl struct {
	bccsp      bccsp.BCCSP
	ctx        *sdf.Ctx
	privatePin string

	sessLock sync.Mutex
	sessPool chan uintptr
	sessions map[uintptr]struct{}

	cacheLock   sync.RWMutex
	handleCache map[string]uint
	keyCache    map[string]bccsp.Key
}

// New WithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func New(library, privatePin string) (bccsp.BCCSP, error) {
	gmPlugin.InitGMPlugin("ccsgm")

	var Bccsp bccsp.BCCSP
	Bccsp, err := gm.New(gm.NewDummyKeyStore(), library)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing fallback GM BCCSP")
	}

	sessPool := make(chan uintptr, defaultSessionCacheSize)
	csp := &impl{
		bccsp: 		 Bccsp,
		privatePin:  privatePin,
		sessPool:    sessPool,
		sessions:    make(map[uintptr]struct{}),
		handleCache: make(map[string]uint),
		keyCache:    make(map[string]bccsp.Key),
	}

	return csp.initialize(library)
}

// KeyGen generates a key using opts.
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}
	// Parse algorithm
	switch opts.(type) {
	case *bccsp.SM2KeyGenOpts:
		ski, pub, err := csp.generateSm2Key()
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating sm2 key")
		}
		k = &sm2Key{ski, pub}
	case *bccsp.SM4KeyGenOpts:
		ski, key, err := csp.generateSymKey()
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating sm4 key")
		}
		k = &sm4Key{ski, key}
	case *bccsp.SM4KeyGenKEKOpts:
		ski, encKey, err := csp.generateSymKeyKEK()
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating sm4 KEK key")
		}
		k = &sm4EncKey{ski, encKey}
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

	var pkk *crypto.PublicKey
	switch opts.(type) {
	case *bccsp.X509PublicKeyImportOpts:
		x509Cert, ok := raw.(*x509.Certificate)
		if !ok {
			return nil, errors.New("[X509PublicKeyImportOpts] Invalid raw material. Expected *x509.Certificate")
		}

		pk := x509Cert.PublicKey

		switch pk.(type) {
		case *ecdsa.PublicKey, *crypto.PublicKey:
			return csp.KeyImport(pk, &bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
		case *sm2.PublicKey:
			return csp.KeyImport(pk, &bccsp.SM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
		default:
			return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, Crypto, SM2]")
		}
	case *bccsp.ECDSAGoPublicKeyImportOpts, *bccsp.SM2PublicKeyImportOpts:
		switch raw.(type) {
		case *sm2.PublicKey:
			sm2Pk := raw.(*sm2.PublicKey)
			pkk = &crypto.PublicKey{
				Curve: sm2Pk.Curve,
				X:     sm2Pk.X,
				Y:     sm2Pk.Y,
			}
		case *crypto.PublicKey:
			pkk = raw.(*crypto.PublicKey)
		case *ecdsa.PublicKey:
			ecdsaPk := raw.(*ecdsa.PublicKey)
			pkk = (*crypto.PublicKey)(unsafe.Pointer(ecdsaPk))
		}
		raw := elliptic.Marshal(pkk.Curve, pkk.X, pkk.Y)
		ski, err := csp.Hash(raw, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "Hash err")
		}
		return &sm2Key{ski, pkk}, nil
	case *bccsp.SM4KeyImportOpts:
		if b, ok := raw.([]byte); !ok {
			return nil, errors.New("SM4KeyImportOpts not support. Supported key: []byte")
		} else {
			ski, err := csp.Hash(b, nil)
			if err != nil {
				return nil, errors.Wrapf(err, "get ski of key error")
			}
			k := sm4Key{
				ski: ski,
				key: b,
			}
			return &k, nil
		}
	case *bccsp.SM4EncKeyImportOpts:
		if b, ok := raw.([]byte); !ok {
			return nil, errors.New("SM4KeyImportOpts not support. Supported key: []byte")
		} else {
			ski, err := csp.Hash(b, nil)
			if err != nil {
				return nil, errors.Wrapf(err, "get ski of key error")
			}
			k := sm4EncKey{
				ski: ski,
				key: b,
			}
			return &k, nil
		}
	default:
		logger.Infof("key import not using SDF, KeyImportOpts:[%v]", opts)
		return csp.bccsp.KeyImport(raw, opts)
	}
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	return nil, nil
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *impl) GetKey(ski []byte) (bccsp.Key, error) {
	if key, ok := csp.cachedKey(ski); ok {
		return key, nil
	}

	pubKey, err := csp.getECKey(ski)
	if err != nil {
		return nil, errors.Wrapf(err, "Key not found using SDF")
	}

	var key bccsp.Key = &sm2Key{ski, pubKey}

	csp.cacheKey(ski, key)
	return key, nil
}

// Hash hashes messages msg using options opts.
func (csp *impl) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()
	return csp.sm3hash(session, msg)
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
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	return csp.signSdf(k.SKI(), digest)
}

// Verify verifies signature against key k and digest
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
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

	switch k.(type) {
	case *sm2Key:
		return csp.verifySdf(k.(*sm2Key).pub, signature, digest)
	default:
		return false, errors.New("not support key type")
	}
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	switch k.(type) {
	case *sm2Key:
		kk := k.(*sm2Key)
		if kk.pub == nil {
			return nil, errors.New("Invalid sm2PublicKey Key. It's pubKey must not be nil.")
		}
		return csp.encryptSM2Sdf(kk.pub, plaintext)
	case *sm4Key:
		kk := k.(*sm4Key)
		return csp.encryptsym(kk.key, plaintext, false)
	case *sm4EncKey:
		kk := k.(*sm4EncKey)
		return csp.encryptsym(kk.key, plaintext, true)
	default:
		return nil, errors.New("Invalid Key. It must be sm2PublicKey or sm4PrivateKey")
	}
	return nil, nil
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	switch k.(type) {
	case *sm2Key:
		return csp.decryptSM2Sdf(k.SKI(), ciphertext)
	case *sm4Key:
		kk := k.(*sm4Key)
		return csp.decryptsym(kk.key, ciphertext, false)
	case *sm4EncKey:
		kk := k.(*sm4EncKey)
		return csp.decryptsym(kk.key, ciphertext, true)
	default:
		return nil, errors.New("Invalid Key. It must be sm2PublicKey or sm4PrivateKey")
	}
	return nil, nil
}
