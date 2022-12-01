package sdf

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/utils"
	gmPlugin "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdf"
	"github.com/pkg/errors"
)

var (
	defaultUid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

func (csp *impl) initialize(library string) (*impl, error) {
	if library == "" {
		return nil, fmt.Errorf("sdf: library path not provided")
	}

	_, err := os.Stat(library)
	if os.IsNotExist(err) {
		return nil, err
	}
	ctx := ctxMap[library]
	if ctx == nil {
		ctx = sdf.New(library)
		if ctx == nil {
			return nil, fmt.Errorf("sdf: instantiation failed for %s", library)
		}
		err = ctx.OpenDevice()
		if err != nil {
			return nil, fmt.Errorf("sdf: instantiation failed for %s", err)
		}
		ctxMap[library] = ctx
	}
	csp.ctx = ctx
	session, err := csp.createSession()
	if err != nil {
		return nil, err
	}

	csp.returnSession(session)
	return csp, nil
}

func (csp *impl) getSession() (session uintptr, err error) {
	for {
		select {
		case session = <-csp.sessPool:
			return
		default:
			// cache is empty (or completely in use), create a new session
			return csp.createSession()
		}
	}
}

func (csp *impl) createSession() (uintptr, error) {
	var sess uintptr
	var err error

	// attempt 10 times to open a session with a 100ms delay after each attempt
	for i := 0; i < 10; i++ {
		sess, err = csp.ctx.OpenSession()
		if err == nil {
			logger.Debugf("Created new sdf session %+v \n", sess)
			break
		}

		logger.Warningf("OpenSession failed, retrying [%s]\n", err)
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return 0, errors.Wrap(err, "OpenSession failed")
	}

	csp.sessLock.Lock()
	csp.sessions[sess] = struct{}{}
	csp.sessLock.Unlock()

	return sess, nil
}

func (csp *impl) closeSession(session uintptr) {
	if err := csp.ctx.CloseSession(session); err != nil {
		logger.Debug("CloseSession failed", err)
	}

	csp.sessLock.Lock()
	defer csp.sessLock.Unlock()

	// purge the handle cache if the last session closes
	delete(csp.sessions, session)
	if len(csp.sessions) == 0 {
		csp.clearCaches()
	}
}

func (csp *impl) returnSession(session uintptr) {
	select {
	case csp.sessPool <- session:
		// returned session back to session cache
	default:
		// have plenty of sessions in cache, dropping
		csp.closeSession(session)
	}
}

func (csp *impl) generateSm2Key() ([]byte, *crypto.PublicKey, error) {
	ctx := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	pub, priv, err := ctx.GenerateKeyPairECC(session, uint(sdf.PARAID), 256)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "sdf generateKeyPairECCEx error")
	}

	pubKey := toGOKey(pub)
	raw := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)

	ski, err := csp.sm3hash(session, raw)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "sdf hash error")
	}
	skiStr := hex.EncodeToString(ski)
	err = ctx.ImportKeyPairECC(session, sdf.SGD_SM2_1, skiStr, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	err = ctx.ImportKeyPairECC(session, sdf.SGD_SM2_3, skiStr, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	return ski, pubKey, nil
}

func (csp *impl) generateSymKey() ([]byte, []byte, error) {
	ctx := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()
	raw, err := ctx.GenerateRandom(session, SM4_KEYLEN)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GenerateRandom error")
	}
	ski, err := csp.sm3hash(session, raw)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "sdf hash error")
	}
	return ski, raw, nil
}

func (csp *impl) generateSymKeyKEK() ([]byte, []byte, error) {
	ctx := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()
	raw, h, err := ctx.GenerateKeyWithKEK(session, SM4_KEYLEN*8, sdf.SGD_SM4_ECB, uint(SM4_IPK_INDEX))
	defer ctx.DestroyKey(session, h)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GenerateRandom error")
	}
	ski, err := csp.sm3hash(session, raw)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "sdf hash error")
	}
	return ski, raw, nil
}

func (csp *impl) signSdf(ski []byte, msg []byte) ([]byte, error) {
	ctx := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	index, err := csp.findKeyPairFromSKI(session, ski)
	if err != nil {
		return nil, fmt.Errorf("Private key not found [%s]", err)
	}
	err = ctx.GetPrivateKeyAccessRight(session, uint(sdf.SGD_SM2), index, []byte(csp.privatePin))
	if err != nil {
		return nil, fmt.Errorf("GetPrivateKeyAccessRight err [%s]", err)
	}
	defer ctx.ReleasePrivateKeyAccessRight(session, uint(sdf.SGD_SM2), index)

	pub, err := ctx.ExportSignPublicKeyECC(session, index)
	if err != nil {
		return nil, err
	}
	// 计算ZA
	digest, err := csp.za(session, pub, msg)
	if err != nil {
		return nil, err
	}
	r, s, err := ctx.InternalSignECC(session, index, digest)
	if err != nil {
		return nil, fmt.Errorf("InternalSignECC  failed [%s]", err)
	}

	R := new(big.Int).SetBytes(r[32:])
	S := new(big.Int).SetBytes(s[32:])
	return utils.MarshalECDSASignature(R, S)
}

func (csp *impl) verifySdf(pubKey *crypto.PublicKey, signature, msg []byte) (bool, error) {
	session, err := csp.getSession()
	if err != nil {
		return false, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	// 转换签名
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, err
	}

	pub := toSDFECCKey(pubKey)
	R := [sdf.ECCref_MAX_LEN]byte{0}
	S := [sdf.ECCref_MAX_LEN]byte{0}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(R[sdf.ECCref_MAX_LEN-len(rBytes):], rBytes)
	copy(S[sdf.ECCref_MAX_LEN-len(sBytes):], sBytes)

	// 计算ZA
	digest, err := csp.za(session, pub, msg)
	if err != nil {
		return false, err
	}

	err = csp.ctx.ExternalVerifyECC(session, uint(sdf.PARAID), pub, digest, R[:], S[:])
	if err != nil {
		return false, err
	}
	return true, nil
}

func (csp *impl) encryptSM2Sdf(pubkey *crypto.PublicKey, plain []byte) ([]byte, error) {
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	pub := toSDFECCKey(pubkey)
	ecccipher, err := csp.ctx.ExternalEncryptECC(session, sdf.PARAID, pub, plain)
	if err != nil {
		return nil, err
	}
	return eccciphertoByte(ecccipher), nil
}

func (csp *impl) decryptSM2Sdf(ski, cipher []byte) ([]byte, error) {
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	index, err := csp.findKeyPairFromSKI(session, ski)
	if err != nil {
		return nil, err
	}
	ecccipher := byteToEcccipher(cipher)
	err = csp.ctx.GetPrivateKeyAccessRight(session, sdf.SGD_SM2, index, []byte(csp.privatePin))
	if err != nil {
		return nil, errors.Wrapf(err, "GetPrivateKeyAccessRight error")
	}
	defer csp.ctx.ReleasePrivateKeyAccessRight(session, sdf.SGD_SM2, index)
	return csp.ctx.ExternalDecryptECC(session, sdf.SGD_SM2_3, index, nil, ecccipher)
}

func (csp *impl) encryptsym(key []byte, plain []byte, enc bool) ([]byte, error) {
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	keyHandle, err := csp.importKey(session, key, enc)
	if err != nil {
		return nil, err
	}
	defer csp.ctx.DestroyKey(session, keyHandle)

	s := pkcs7Padding(plain)
	iv, err := csp.ctx.GenerateRandom(session, SM4_BLOCKSIZE)
	if err != nil {
		return nil, err
	}
	_, cipher, err := csp.ctx.Encrypt(session, keyHandle, sdf.SGD_SM4_CBC, iv, s)
	ciphertext := append(iv, cipher...)
	return ciphertext, err
}

func (csp *impl) decryptsym(key []byte, cipher []byte, enc bool) ([]byte, error) {
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	keyHandle, err := csp.importKey(session, key, enc)
	if err != nil {
		return nil, err
	}
	defer csp.ctx.DestroyKey(session, keyHandle)
	iv := cipher[:SM4_BLOCKSIZE]
	cipher = cipher[SM4_BLOCKSIZE:]
	_, plain, err := csp.ctx.Decrypt(session, keyHandle, sdf.SGD_SM4_CBC, iv, cipher)
	if err != nil {
		return nil, err
	}
	return pkcs7UnPadding(plain)
}

func (csp *impl) importKey(session uintptr, key []byte, enc bool) (uintptr, error) {
	var keyHandle uintptr
	var err error
	if !enc {
		keyHandle, err = csp.ctx.ImportKey(session, key)
	} else {
		keyHandle, err = csp.ctx.ImportKeyWithKEK(session, sdf.SGD_SM4_ECB, uint(SM4_IPK_INDEX), key)
	}
	return keyHandle, err
}

// This function can probably be adapted for both EC and RSA keys.
func (csp *impl) getECKey(ski []byte) (pubKey *crypto.PublicKey, err error) {
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	index, err := csp.findKeyPairFromSKI(session, ski)
	if err != nil {
		return nil, errors.Wrapf(err, "findKeyPairFromSKI err")
	}
	err = csp.ctx.GetPrivateKeyAccessRight(session, uint(sdf.SGD_SM2), index, []byte(csp.privatePin))
	if err != nil {
		return nil, fmt.Errorf("GetPrivateKeyAccessRight err [%s]", err)
	}
	defer csp.ctx.ReleasePrivateKeyAccessRight(session, uint(sdf.SGD_SM2), index)
	pub, err := csp.ctx.ExportSignPublicKeyECC(session, index)
	if err != nil {
		return nil, errors.Wrapf(err, "ExportSignPublicKeyECC err")
	}
	pubKey = &crypto.PublicKey{
		Curve: gmPlugin.NewSm2Curve().P256Sm2(),
		X:     new(big.Int).SetBytes(pub.X[32:]),
		Y:     new(big.Int).SetBytes(pub.Y[32:]),
	}
	return pubKey, nil
}

func (csp *impl) za(session uintptr, key *sdf.ECCPublicKey, data []byte) ([]byte, error) {
	err := csp.ctx.HashInit(session, sdf.SGD_SM3, key, defaultUid)
	if err != nil {
		return nil, err
	}
	err = csp.ctx.HashUpdate(session, data)
	if err != nil {
		return nil, err
	}
	return csp.ctx.HashFinal(session)
}
func (csp *impl) sm3hash(session uintptr, data []byte) ([]byte, error) {
	ctx := csp.ctx
	err := ctx.HashInit(session, sdf.SGD_SM3, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "sdf hashInit error")
	}
	tmpData := data
	for len(tmpData) > 2048 {
		hashData := tmpData[:2048]
		err = ctx.HashUpdate(session, hashData)
		if err != nil {
			return nil, errors.Wrapf(err, "sdf hashUpdate error")
		}
		tmpData = tmpData[2048:]
	}
	if len(tmpData) > 0 {
		err = ctx.HashUpdate(session, tmpData)
		if err != nil {
			return nil, errors.Wrapf(err, "sdf hashUpdate error")
		}
	}
	digest, err := ctx.HashFinal(session)
	if err != nil {
		return nil, errors.Wrapf(err, "sdf hashFinal error")
	}
	return digest, nil
}

func (csp *impl) findKeyPairFromSKI(session uintptr, ski []byte) (index uint, err error) {
	// check for cached handle
	if handle, ok := csp.cachedHandle(ski); ok {
		return handle, nil
	}
	skiStr := hex.EncodeToString(ski)
	index, err = csp.ctx.GetIndex(session, sdf.SGD_SM2, skiStr)
	if err == nil {
		// cache the found handle
		csp.cacheHandle(ski, index)
		return index, nil
	}
	return 0, errors.Wrapf(err, "findKeyPairFromSKI error")
}

func (csp *impl) cachedHandle(ski []byte) (uint, bool) {
	cacheKey := hex.EncodeToString(ski)
	csp.cacheLock.RLock()
	defer csp.cacheLock.RUnlock()

	handle, ok := csp.handleCache[cacheKey]
	return handle, ok
}

func (csp *impl) cacheHandle(ski []byte, handle uint) {
	cacheKey := hex.EncodeToString(ski)
	csp.cacheLock.Lock()
	defer csp.cacheLock.Unlock()

	csp.handleCache[cacheKey] = handle
}

func (csp *impl) clearCaches() {
	csp.cacheLock.Lock()
	defer csp.cacheLock.Unlock()
	csp.handleCache = map[string]uint{}
	csp.keyCache = map[string]bccsp.Key{}
}

func (csp *impl) handleSessionReturn(err error, session uintptr) {
	if err != nil {
		if strings.Contains(err.Error(), "SDR_") {
			logger.Infof("SDF session invalidated, closing session: %v", err)
			csp.closeSession(session)
			return
		}
	}
	csp.returnSession(session)
}
