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
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"sync"
	"time"
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	gmPlugin "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	cpt "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

const keyNotExist = "key not exist"

type Err string

func (e Err) Error() string {
	return string(e)
}

const SM4_KeyLen = 16

var regex = regexp.MustCompile(".*0xB.:\\sCKR.+")

func (csp *impl) initialize(opts PKCS11Opts) (*impl, error) {
	if opts.Library == "" {
		return nil, fmt.Errorf("pkcs11: library path not provided")
	}
	_, err := os.Stat(opts.Library)
	if os.IsNotExist(err) {
		return nil, err
	}
	ctx := ctxMap[opts.Library]
	if ctx == nil {
		ctx = pkcs11.New(opts.Library)
		if ctx == nil {
			return nil, fmt.Errorf("pkcs11: instantiation failed for %s", opts.Library)
		}
		if err := ctx.Initialize(); err != nil {
			return nil, fmt.Errorf("initialize failed: %v", err)
		}
		ctxMap[opts.Library] = ctx
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, errors.Wrap(err, "pkcs11: get slot list")
	}

	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil || opts.Label != info.Label {
			continue
		}

		csp.slot = s
		csp.ctx = ctx
		csp.pin = opts.Pin

		session, err := csp.createSession()
		if err != nil {
			return nil, err
		}

		csp.returnSession(session)
		return csp, nil
	}

	return nil, errors.Errorf("pkcs11: could not find token with label %s", opts.Label)
}

func (csp *impl) getSession() (session pkcs11.SessionHandle, err error) {
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

func (csp *impl) createSession() (pkcs11.SessionHandle, error) {
	var sess pkcs11.SessionHandle
	var err error

	// attempt 10 times to open a session with a 100ms delay after each attempt
	for i := 0; i < 10; i++ {
		sess, err = csp.ctx.OpenSession(csp.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err == nil {
			logger.Debugf("Created new pkcs11 session %+v on slot %d\n", sess, csp.slot)
			break
		}

		logger.Warningf("OpenSession failed, retrying [%s]\n", err)
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return 0, errors.Wrap(err, "OpenSession failed")
	}

	err = csp.ctx.Login(sess, pkcs11.CKU_USER, csp.pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		csp.ctx.CloseSession(sess)
		return 0, errors.Wrap(err, "Login failed")
	}
	csp.sessLock.Lock()
	csp.sessions[sess] = struct{}{}
	csp.sessLock.Unlock()

	return sess, nil
}

func (csp *impl) closeSession(session pkcs11.SessionHandle) {
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

func (csp *impl) returnSession(session pkcs11.SessionHandle) {
	select {
	case csp.sessPool <- session:
		// returned session back to session cache
	default:
		// have plenty of sessions in cache, dropping
		csp.closeSession(session)
	}
}

// Look for an EC key by SKI, stored in CKA_ID or CKA_LABEL
// This function can probably be adapted for both symmetric keys (AES, SM4) and Asymmetric keys (EC, SM2).
func (csp *impl) getKey(ski []byte) (key bccsp.Key, err error) {

	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	// 1. querying key by ski
	keyObj, isPriv, err := csp.findKeyBySKI(session, ski)
	if err != nil {
		return nil, err
	}

	// 2. determine key class and type
	cls, tp, err := csp.getKeyType(session, keyObj)
	if err != nil {
		return nil, err
	}

	// 3. generate key depending on different key type
	if cls == pkcs11.CKO_SECRET_KEY {

		privKey, err := csp.getSymKeyValue(session, keyObj)
		if err != nil {
			return nil, fmt.Errorf("Error querying symetric key value: [%s] for SKI [%s]", err, hex.EncodeToString(ski))
		}

		switch tp {
		case pkcs11.CKK_AES:
			key = &aesPrivateKey{privKey: privKey, exportable: false}
		case CKK_SM4:
			key = &sm4PrivateKey{key: privKey}
		default:
			return nil, fmt.Errorf("not supported symetric key type: [%d] for SKI [%s]", tp, hex.EncodeToString(ski))
		}

	} else if cls == pkcs11.CKO_PUBLIC_KEY {

		curve, x, y, err := csp.getGoCurve(session, keyObj)
		if err != nil {
			return nil, err
		}

		switch tp {
		case pkcs11.CKK_EC:
			pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

			if isPriv {
				key = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pubKey}}
			} else {
				key = &ecdsaPublicKey{ski, pubKey}
			}
		case CKK_SM2:
			pubkey := &cpt.PublicKey{Curve: curve, X: x, Y: y}

			if isPriv {
				key = &sm2PrivateKey{ski, sm2PublicKey{ski, pubkey}}
			} else {
				key = &sm2PublicKey{ski, pubkey}
			}
		default:
			return nil, fmt.Errorf("not supported asymetric key type: [%d] for SKI [%s]", tp, hex.EncodeToString(ski))
		}
	}

	return
}

// RFC 5480, 2.1.1.1. Named Curve
//
// secp224r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
// secp256r1 OBJECT IDENTIFIER ::= {
//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//   prime(1) 7 }
//
// secp384r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
// secp521r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(oidNamedCurveP256SM2):
		return gmPlugin.NewSm2Curve().P256Sm2()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case gmPlugin.NewSm2Curve().P256Sm2():
		return oidNamedCurveP256SM2, true
	}

	return nil, false
}

func (csp *impl) generateECKey(curve asn1.ObjectIdentifier, ephemeral bool) (ski []byte, pubKey *ecdsa.PublicKey, err error) {
	ski, C, X, Y, err := csp.generateAsymKey(curve, ephemeral, EC)
	if err != nil {
		err = fmt.Errorf("Failed to generate EC key [%s]", err)
		return
	}

	logger.Debugf("Generating EC key for ski [%s]", hex.EncodeToString(ski))
	pubKey = &ecdsa.PublicKey{Curve: C, X: X, Y: Y}
	return
}

func (csp *impl) generateSM2Key(curve asn1.ObjectIdentifier, ephemeral bool) (ski []byte, pubKey *cpt.PublicKey, err error) {
	ski, C, X, Y, err := csp.generateAsymKey(curve, ephemeral, SM2)
	if err != nil {
		err = fmt.Errorf("Failed to generate SM2 key [%s]", err)
		return
	}

	logger.Debugf("Generating SM2 key for ski [%s]", hex.EncodeToString(ski))
	pubKey = &cpt.PublicKey{Curve: C, X: X, Y: Y}
	return
}

func (csp *impl) generateAsymKey(curve asn1.ObjectIdentifier, ephemeral bool,
	keyType KeyType) (ski []byte, C elliptic.Curve, X, Y *big.Int, err error) {

	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	keylabel := ""
	updateSKI := false
	if csp.altId == "" {
		// Generate using the SKI process and then make keypair immutable according to csp.immutable
		keylabel = fmt.Sprintf("BCP%s", nextIDCtr().Text(16))
		updateSKI = true
	} else if csp.altId != "" {
		// Generate the key pair using AltID process.
		// No need to worry about immutable since AltID is used with Write-Once HSMs
		keylabel = csp.altId
		updateSKI = false
	}

	marshaledOID, err := asn1.Marshal(curve)
	if err != nil {
		err = fmt.Errorf("Could not marshal OID [%s]", err.Error())
		return
	}

	var keyt uint
	var keyGenMech uint
	var hashMech HashMech

	switch keyType {
	case SM2:
		keyt = CKK_SM2
		keyGenMech = CKM_SM2_KEY_PAIR_GEN
		hashMech = SM3
	case EC:
		keyt = pkcs11.CKK_EC
		keyGenMech = pkcs11.CKM_EC_KEY_PAIR_GEN
		hashMech = SHA256
	default:
		err = fmt.Errorf("unsupported key type, only for [EC, SM2]")
		return
	}

	pubkeyT := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyt),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keylabel)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keylabel),
	}

	prvkeyT := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyt),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keylabel)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keylabel),

		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}

	pub, prv, err := p11lib.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(keyGenMech, nil)}, pubkeyT, prvkeyT)
	if err != nil {
		err = fmt.Errorf("P11: keypair generate failed [%s]", err)
		return
	}

	ecpt, _, err := csp.ecPoint(session, pub)
	if err != nil {
		err = fmt.Errorf("Error querying EC-point: [%s]", err)
		return
	}

	if ski, err = csp.hashPKCS11(ecpt, hashMech); err != nil {
		err = fmt.Errorf("Failed to compute ski by ec-point [%s]", err)
		return
	}

	if updateSKI {
		// set CKA_ID of the both keys to SKI(public key) and CKA_LABEL to hex string of SKI
		setskiT := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(ski)),
		}

		logger.Infof("Generated new P11 key, SKI %x\n", ski)
		if err = p11lib.SetAttributeValue(session, pub, setskiT); err != nil {
			err = fmt.Errorf("P11: set-ID-to-SKI[public] failed [%s]", err)
			return
		}
		if err = p11lib.SetAttributeValue(session, prv, setskiT); err != nil {
			err = fmt.Errorf("P11: set-ID-to-SKI[private] failed [%s]", err)
			return
		}

		//Set CKA_Modifible to false for both public key and private keys
		if csp.immutable {
			setCKAModifiable := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
			}

			if _, pubCopyerror := p11lib.CopyObject(session, pub, setCKAModifiable); pubCopyerror != nil {
				err = fmt.Errorf("P11: Public Key copy failed with error [%s] . Please contact your HSM vendor", pubCopyerror)
				return
			}
			if pubKeyDestroyError := p11lib.DestroyObject(session, pub); pubKeyDestroyError != nil {
				err = fmt.Errorf("P11: Public Key destroy failed with error [%s]. Please contact your HSM vendor", pubKeyDestroyError)
				return
			}

			if _, prvCopyerror := p11lib.CopyObject(session, prv, setCKAModifiable); prvCopyerror != nil {
				err = fmt.Errorf("P11: Private Key copy failed with error [%s]. Please contact your HSM vendor", prvCopyerror)
				return
			}
			if prvKeyDestroyError := p11lib.DestroyObject(session, prv); prvKeyDestroyError != nil {
				err = fmt.Errorf("P11: Private Key destroy failed with error [%s]. Please contact your HSM vendor", prvKeyDestroyError)
				return
			}
		}
	}

	if C = namedCurveFromOID(curve); C == nil {
		err = fmt.Errorf("Cound not recognize Curve from OID")
		return
	}
	if X, Y = elliptic.Unmarshal(C, ecpt); X == nil {
		err = fmt.Errorf("Failed Unmarshaling Public Key")
		return
	}

	if logger.IsEnabledFor(logging.DEBUG) {
		listAttrs(p11lib, session, prv)
		listAttrs(p11lib, session, pub)
	}

	return
}

func (csp *impl) generateAESKey(length int, ephemeral bool) (ski, privKey []byte, err error) {
	if ski, privKey, err = csp.generateSymKey(length, ephemeral, AES); err != nil {
		return nil, nil, fmt.Errorf("Failed to generate AES key [%s]", err)
	}
	logger.Debugf("Generating AES key for ski [%s]", hex.EncodeToString(ski))
	return
}

func (csp *impl) generateSM4Key(ephemeral bool) (ski, privKey []byte, err error) {
	if ski, privKey, err = csp.generateSymKey(SM4_KeyLen, ephemeral, SM4); err != nil {
		return nil, nil, fmt.Errorf("Failed to generate sm4 key [%s]", err)
	}
	logger.Debugf("Generating SM4 key for ski [%s]", hex.EncodeToString(ski))
	return
}

func (csp *impl) generateSymKey(length int, ephemeral bool, keyType KeyType) (ski, privKey []byte, err error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	var keyt uint
	var genKeyMech uint
	var hashMech HashMech

	switch keyType {
	case SM4:
		keyt = CKK_SM4
		genKeyMech = CKM_SM4_KEY_GEN
		hashMech = SM3
	case AES:
		keyt = pkcs11.CKK_AES
		genKeyMech = pkcs11.CKM_AES_KEY_GEN
		hashMech = SHA256
	}

	keyT := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyt),

		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, length),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(genKeyMech, nil)}
	key, err := p11lib.GenerateKey(session, mech, keyT)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: symmetric key generate failed [%s]", err)
	}

	if privKey, err = csp.getSymKeyValue(session, key); err != nil {
		return nil, nil, fmt.Errorf("Error querying symmetric value: [%s]", err)
	} else if len(privKey) == 0 {
		return nil, nil, fmt.Errorf("empty value from symmetric key")
	}

	ski, err = csp.hashPKCS11(privKey, hashMech)
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating symmetric ski: [%s]", err)
	}

	setskiT := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(ski)),
	}

	logger.Infof("Generated new P11 symmetric key, SKI %x\n", ski)
	if err = p11lib.SetAttributeValue(session, key, setskiT); err != nil {
		return nil, nil, fmt.Errorf("P11 symmetric: set-ID-to-SKI failed [%s]", err)
	}

	if logger.IsEnabledFor(logging.DEBUG) {
		listAttrs(p11lib, session, key)
	}

	return
}

type KeyType int8

const (
	EC KeyType = iota
	SM2
	AES
	SM4
)

func (csp *impl) createECKey(curve elliptic.Curve, x, y *big.Int, privKey []byte, ephemeral bool,
	isPublicKey bool) (ski []byte, keyObj pkcs11.ObjectHandle, err error) {
	logger.Debugf("Creating EC key for ski [%s]", hex.EncodeToString(ski))
	if ski, keyObj, err = csp.createAsymKey(curve, x, y, privKey, ephemeral, isPublicKey, EC); err != nil {
		return nil, 0, fmt.Errorf("Failed to create EC key [%s]", err)
	}
	return
}

func (csp *impl) createSM2Key(curve elliptic.Curve, x, y *big.Int, privKey []byte, ephemeral bool,
	isPublicKey bool) (ski []byte, keyObj pkcs11.ObjectHandle, err error) {
	logger.Debugf("Creating SM2 key for ski [%s]", hex.EncodeToString(ski))
	if ski, keyObj, err = csp.createAsymKey(curve, x, y, privKey, ephemeral, isPublicKey, SM2); err != nil {
		return nil, 0, fmt.Errorf("Failed to create sm2 key [%s]", err)
	}
	return
}

func (csp *impl) createAsymKey(curve elliptic.Curve, x, y *big.Int, privKey []byte,
	ephemeral, isPublicKey bool, kType KeyType) (ski []byte, keyObj pkcs11.ObjectHandle, err error) {

	// 1. get session
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, 0, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	// 2. prepare template 'pubkeyT' and 'prvKeyT'
	// 2.1 compute marshaledOID for attribute: CKA_EC_PARAMS
	curveOID, ok := oidFromNamedCurve(curve)
	if !ok {
		err = fmt.Errorf("Failed to get curve oid")
		return
	}
	marshaledOID, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, 0, fmt.Errorf("Could not marshal OID [%s]", err.Error())
	}

	// 2.2 compute ski and ecPoint
	var kt uint
	var hashMech HashMech
	switch kType {
	case EC:
		kt = pkcs11.CKK_EC
		hashMech = SHA256
	case SM2:
		kt = CKK_SM2
		hashMech = SM3
	default:
		return nil, 0, fmt.Errorf("Unsupported key type, only for [EC, SM2]")
	}

	ecPt := elliptic.Marshal(curve, x, y)
	if ski, err = csp.hashPKCS11(ecPt, hashMech); err != nil {
		return nil, 0, fmt.Errorf("Failed to hash %s [%s]", reflect.ValueOf(hashMech), err.Error())
	}
	ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...) // ec-point doesn't include two extra bytes when computing ski

	// 2.3 create 'pubkeyT' and 'prvKeyT'
	pubkeyT := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, kt),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(ski)),

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	}

	prvKeyT := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKey), // 该属性存放私钥的D值

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, kt),

		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(ski)),

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral), // 经过测试 CKA_TOKEN 仅为 false 才可以跑通
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TRUSTED, true),

		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}

	// 3. create key-obj depending on key type (private or public)
	if isPublicKey {
		logger.Debugf("Importing public key for ski [%s]", hex.EncodeToString(ski))

		if keyObj, err = p11lib.CreateObject(session, pubkeyT); err != nil {
			return nil, 0, fmt.Errorf("Failed to create public key object [%s]", err.Error())
		}
	} else {
		logger.Debugf("Importing public and private key for ski [%s]", hex.EncodeToString(ski))

		if _, err = p11lib.CreateObject(session, prvKeyT); err != nil {
			return nil, 0, fmt.Errorf("Failed to create private key object [%s]", err.Error())
		}

		if keyObj, err = p11lib.CreateObject(session, pubkeyT); err != nil {
			return nil, 0, fmt.Errorf("Failed to create public key object [%s]", err.Error())
		}
	}

	if logger.IsEnabledFor(logging.DEBUG) {
		listAttrs(p11lib, session, keyObj)
	}

	return
}

func (csp *impl) genSKIAsymKey(curve elliptic.Curve, x, y *big.Int, kType KeyType) (ski []byte, err error) {
	ecPt := elliptic.Marshal(curve, x, y)

	var hashMech HashMech
	switch kType {
	case EC:
		hashMech = SHA256
	case SM2:
		hashMech = SM3
	default:
		return nil, fmt.Errorf("Unsupported key type, only for [EC, SM2]")
	}

	if ski, err = csp.hashPKCS11(ecPt, hashMech); err != nil {
		return nil, fmt.Errorf("Failed to hash %s [%s]", reflect.ValueOf(hashMech), err.Error())
	}

	return
}

func (csp *impl) signP11AsymKey(ski []byte, msg []byte, keyType KeyType) (R, S *big.Int, err error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	privateKey, err := csp.findKeyFromSKIAndClass(session, ski, privateKeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("Private key not found [%s] for ski [%s]", err, hex.EncodeToString(ski))
	}

	var signMech uint
	switch keyType {
	case EC:
		signMech = pkcs11.CKM_ECDSA
	case SM2:
		signMech = CKM_SM3_SM2
	}

	if err = p11lib.SignInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(signMech, nil)},
		privateKey); err != nil {
		return nil, nil, fmt.Errorf("Sign-initialize failed [%s]", err)
	}

	sig, err := p11lib.Sign(session, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: asymmetric key sign failed [%s]", err)
	}

	R = new(big.Int)
	S = new(big.Int)
	R.SetBytes(sig[0 : len(sig)/2])
	S.SetBytes(sig[len(sig)/2:])
	return
}

func (csp *impl) signP11EC(ski []byte, msg []byte) (R, S *big.Int, err error) {
	logger.Debugf("Sign EC key for ski [%s]", hex.EncodeToString(ski))
	if R, S, err = csp.signP11AsymKey(ski, msg, EC); err != nil {
		return nil, nil, fmt.Errorf("Failed to sign EC key [%s]", err)
	}
	return
}

func (csp *impl) signP11SM2(ski []byte, msg []byte) (R, S *big.Int, err error) {
	logger.Debugf("Create SM2 key for ski [%s]", hex.EncodeToString(ski))
	if R, S, err = csp.signP11AsymKey(ski, msg, SM2); err != nil {
		return nil, nil, fmt.Errorf("Failed to sign SM2 key [%s]", err)
	}
	return
}

func (csp *impl) verifyP11AsymKey(ski, msg []byte, R, S *big.Int, byteSize int,
	curve elliptic.Curve, x, y *big.Int, keyType KeyType) (ok bool, err error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return false, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	var verifyMech uint
	switch keyType {
	case SM2:
		verifyMech = CKM_SM3_SM2
	case EC:
		verifyMech = pkcs11.CKM_ECDSA
	default:
		return false, fmt.Errorf("unsupported key type, only for [SM2, EC]")
	}

	publicKey, err := csp.findKeyFromSKIAndClass(session, ski, publicKeyType)
	if err == Err(keyNotExist) {
		logger.Infof("Public key not found [%s] for ski [%s], trying to creat key object", err, hex.EncodeToString(ski))

		if _, publicKey, err = csp.createAsymKey(curve, x, y, nil, true, true, keyType); err != nil {
			return false, fmt.Errorf("Failed to create SM2 public key object [%s]", err.Error())
		}
		// todo: because of concurrency problem in the current function, we don't destroy the created key-obj unless there is a better way to solve it
	} else if err != nil {
		return false, fmt.Errorf("Failed to find public key from ski [%s] for error [%s]", hex.EncodeToString(ski), err.Error())
	}

	r := R.Bytes()
	s := S.Bytes()

	// Pad front of R and S with Zeroes if needed
	sig := make([]byte, 2*byteSize)
	copy(sig[byteSize-len(r):byteSize], r)
	copy(sig[2*byteSize-len(s):], s)

	if err = p11lib.VerifyInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(verifyMech, nil)}, publicKey); err != nil {
		return false, fmt.Errorf("PKCS11: asymmetric key Verify-initialize [%s]", err)
	}

	if err = p11lib.Verify(session, msg, sig); err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("PKCS11: asymmetric key Verify failed [%s]", err)
	}

	return true, nil
}

func (csp *impl) verifyP11ECDSA(ski []byte, msg []byte, R, S *big.Int, byteSize int) (bool, error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return false, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	logger.Debugf("Verify ECDSA\n")

	publicKey, err := csp.findKeyFromSKIAndClass(session, ski, publicKeyType)
	if err != nil {
		return false, fmt.Errorf("Public key not found [%s]", err)
	}

	r := R.Bytes()
	s := S.Bytes()

	// Pad front of R and S with Zeroes if needed
	sig := make([]byte, 2*byteSize)
	copy(sig[byteSize-len(r):byteSize], r)
	copy(sig[2*byteSize-len(s):], s)

	err = p11lib.VerifyInit(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
		publicKey,
	)
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify-initialize [%s]", err)
	}
	err = p11lib.Verify(session, msg, sig)
	if err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify failed [%s]", err)
	}

	return true, nil
}

func (csp *impl) verifyP11EC(ski, msg []byte, R, S *big.Int, byteSize int,
	curve elliptic.Curve, x, y *big.Int) (ok bool, err error) {
	logger.Debugf("Verify EC key\n")
	if ok, err = csp.verifyP11AsymKey(ski, msg, R, S, byteSize, curve, x, y, EC); err != nil {
		return false, fmt.Errorf("Failed to verify EC key [%s]", err)
	}
	return
}

func (csp *impl) verifyP11SM2(ski, msg []byte, R, S *big.Int, byteSize int,
	curve elliptic.Curve, x, y *big.Int) (ok bool, err error) {
	logger.Debugf("Verify SM2 key\n")
	if ok, err = csp.verifyP11AsymKey(ski, msg, R, S, byteSize, curve, x, y, SM2); err != nil {
		return false, fmt.Errorf("Failed to verify SM2 key [%s]", err)
	}
	return
}

func (csp *impl) encryptSM2Key(ski []byte, plaintext []byte, pk *cpt.PublicKey) (ciphertext []byte, err error) {
	// 1. get key-obj from library
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	logger.Debugf("Encrypt Asymmetric SM2 key\n")

	keyObj, err := csp.findKeyFromSKIAndClass(session, ski, publicKeyType)
	if err == Err(keyNotExist) {
		logger.Infof("Public key not found [%s] for ski [%s], trying to creat key object", err, hex.EncodeToString(ski))

		if _, keyObj, err = csp.createSM2Key(pk.Curve, pk.X, pk.Y, nil, true, true); err != nil {
			return nil, fmt.Errorf("Failed to create SM2 public key object [%s]", err.Error())
		}
		// todo: because of concurrency problem in the current function, we don't destroy the created key-obj unless there is a better way to solve it
	} else if err != nil {
		return nil, fmt.Errorf("Failed to find SM2 public key for err [%s]", err)
	}

	// 2. encrypt using pkcs11
	if err = p11lib.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_SM2_RAW, nil)}, keyObj); err != nil {
		return nil, fmt.Errorf("PKCS11: Asymmetric Encrypt-initialize [%s]", err)
	}

	if ciphertext, err = p11lib.Encrypt(session, plaintext); err != nil {
		return nil, fmt.Errorf("PKCS11: Asymmetric encrypt failed [%s]", err)
	}

	return
}

func (csp *impl) decryptSM2key(ski []byte, ciphertext []byte) (plaintext []byte, err error) {
	// 1. get key-obj from library
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	logger.Debugf("Decrypt Asymmetric\n")

	keyObj, err := csp.findKeyFromSKIAndClass(session, ski, privateKeyType)
	if err != nil {
		return nil, fmt.Errorf("private key not found [%s]", err)
	}

	// 2. decrypt using pkcs11
	if err = p11lib.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_SM2_RAW, nil)}, keyObj); err != nil {
		return nil, fmt.Errorf("PKCS11: Asymmetric Decrypt-initialize [%s]", err)
	}

	if plaintext, err = p11lib.Decrypt(session, ciphertext); err != nil {
		return nil, fmt.Errorf("PKCS11: Asymmetric decrypt failed [%s]", err)
	}

	return
}

func (csp *impl) decryptSymmetric(ski []byte, ciphertext []byte, mode symEncryptMode) (plaintext []byte, err error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	logger.Debugf("Decrypt Symmetric\n")

	keyObj, err := csp.findKeyFromSKIAndClass(session, ski, secretKeyType)
	if err != nil {
		return nil, fmt.Errorf("secret key not found [%s]", err)
	}

	if err = p11lib.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mode.symEncryptMechanism, mode.x)}, keyObj); err != nil {
		return nil, fmt.Errorf("PKCS11: Symmetric Decrypt-initialize [%s]", err)
	}

	if plaintext, err = p11lib.Decrypt(session, ciphertext); err != nil {
		return nil, fmt.Errorf("PKCS11: Symmetric decrypt failed [%s]", err)
	}

	return
}

func (csp *impl) encryptSymmetric(ski []byte, plaintext []byte, mode symEncryptMode, ivRandom bool) (ciphertext []byte, err error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	logger.Debugf("Encrypt Symmetric\n")

	keyObj, err := csp.findKeyFromSKIAndClass(session, ski, secretKeyType)
	if err != nil {
		return nil, fmt.Errorf("secret key not found [%s]", err)
	}

	if ivRandom {
		if mode.x, err = p11lib.GenerateRandom(session, BlockSize); err != nil {
			return nil, fmt.Errorf("Failed to generate random bytes [%s]", err)
		}
	}

	if err = p11lib.EncryptInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(mode.symEncryptMechanism, mode.x)},
		keyObj); err != nil {
		return nil, fmt.Errorf("PKCS11: Symmetric Encrypt-initialize [%s]", err)
	}

	ct, err := p11lib.Encrypt(session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("PKCS11: Symmetric encrypt failed [%s]", err)
	}

	ciphertext = make([]byte, BlockSize+len(ct))
	copy(ciphertext[:BlockSize], mode.x)
	copy(ciphertext[BlockSize:], ct)
	return
}

type HashMech int8

const (
	SHA224 HashMech = iota
	SHA256
	SHA384
	SHA512
	SM3
)

func (csp *impl) hashPKCS11(msg []byte, hashMech HashMech) (digest []byte, err error) {
	p11lib := csp.ctx
	session, err := csp.getSession()
	if err != nil {
		return nil, err
	}
	defer func() { csp.handleSessionReturn(err, session) }()

	var mech uint
	switch hashMech {
	case SHA224:
		mech = pkcs11.CKM_SHA224
	case SHA256:
		mech = pkcs11.CKM_SHA256
	case SHA384:
		mech = pkcs11.CKM_SHA384
	case SHA512:
		mech = pkcs11.CKM_SHA512
	case SM3:
		mech = CKM_SM3
	}

	if err = p11lib.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}); err != nil {
		return nil, fmt.Errorf("PKCS11: Digest-initialize [%s]", err)
	}

	if digest, err = p11lib.Digest(session, msg); err != nil {
		return nil, fmt.Errorf("PKCS11: Digest failed [%s]", err)
	}

	return
}

type keyClass int8

const (
	publicKeyType keyClass = iota
	privateKeyType
	secretKeyType
)

func (csp *impl) cachedHandle(keyType keyClass, ski []byte) (pkcs11.ObjectHandle, bool) {
	cacheKey := hex.EncodeToString(append([]byte{byte(keyType)}, ski...))
	csp.cacheLock.RLock()
	defer csp.cacheLock.RUnlock()

	handle, ok := csp.handleCache[cacheKey]
	return handle, ok
}

func (csp *impl) cacheHandle(keyType keyClass, ski []byte, handle pkcs11.ObjectHandle) {
	cacheKey := hex.EncodeToString(append([]byte{byte(keyType)}, ski...))
	csp.cacheLock.Lock()
	defer csp.cacheLock.Unlock()

	csp.handleCache[cacheKey] = handle
}

func (csp *impl) clearCaches() {
	csp.cacheLock.Lock()
	defer csp.cacheLock.Unlock()
	csp.handleCache = map[string]pkcs11.ObjectHandle{}
	csp.keyCache = map[string]bccsp.Key{}
}

func (csp *impl) findKeyBySKI(session pkcs11.SessionHandle, ski []byte) (keyObj pkcs11.ObjectHandle, isPriv bool, err error) {
	// 1. firstly, we try to find the asymmetric key
	isPriv = true
	if _, err = csp.findKeyFromSKIAndClass(session, ski, privateKeyType); err != nil {
		isPriv = false
		logger.Debugf("Private key not found [%s] for SKI [%s], looking for Public key", err, hex.EncodeToString(ski))
	}
	if keyObj, err = csp.findKeyFromSKIAndClass(session, ski, publicKeyType); err == nil {
		return
	}

	// 2. then we try to find the symmetric key
	logger.Debugf("Public key not found [%s] for SKI [%s], looking for symmetric key", err, hex.EncodeToString(ski))
	if keyObj, err = csp.findKeyFromSKIAndClass(session, ski, secretKeyType); err != nil {
		err = fmt.Errorf("Key not found [%s] for SKI [%s]", err, hex.EncodeToString(ski))
		return
	}

	return
}

func (csp *impl) findKeyFromSKIAndClass(session pkcs11.SessionHandle, ski []byte, kt keyClass) (pkcs11.ObjectHandle, error) {
	// 1. determine query param: CKA_CLASS and CKA_ID
	keyId := ski
	if csp.altId != "" {
		keyId = []byte(csp.altId)
	}

	if handle, ok := csp.cachedHandle(kt, keyId); ok {
		return handle, nil
	}

	kcls := pkcs11.CKO_PUBLIC_KEY
	if kt == privateKeyType {
		kcls = pkcs11.CKO_PRIVATE_KEY
	} else if kt == secretKeyType {
		kcls = pkcs11.CKO_SECRET_KEY
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, kcls),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
	}

	// 2. query key from library by CKA_ID
	var err error
	if err = csp.ctx.FindObjectsInit(session, template); err != nil {
		return 0, err
	}
	defer csp.ctx.FindObjectsFinal(session)

	// single session instance, assume one hit only
	var objs []pkcs11.ObjectHandle
	if objs, _, err = csp.ctx.FindObjects(session, 1); err != nil {
		return 0, err
	}

	// 3. query key obj by CKA_LABEL
	if len(objs) == 0 {
		logger.Debugf("querying key object by [CKA_CLASS, CKA_LABEL], ski [%s]", hex.Dump(keyId))

		csp.ctx.FindObjectsFinal(session)

		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, kcls),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(keyId)),
		}

		if err = csp.ctx.FindObjectsInit(session, template); err != nil {
			return 0, err
		}

		if objs, _, err = csp.ctx.FindObjects(session, 1); err != nil {
			return 0, err
		}

		if len(objs) == 0 {
			return 0, Err(keyNotExist)
		}
	}

	// cache the found handle
	csp.cacheHandle(kt, keyId, objs[0])

	return objs[0], nil
}

// Fairly straightforward EC-point query, other than opencryptoki
// mis-reporting length, including the 04 Tag of the field following
// the SPKI in EP11-returned MACed publickeys:
//
// attr type 385/x181, length 66 b  -- SHOULD be 1+64
// EC point:
// 00000000  04 ce 30 31 6d 5a fd d3  53 2d 54 9a 27 54 d8 7c
// 00000010  d9 80 35 91 09 2d 6f 06  5a 8e e3 cb c0 01 b7 c9
// 00000020  13 5d 70 d4 e5 62 f2 1b  10 93 f7 d5 77 41 ba 9d
// 00000030  93 3e 18 3e 00 c6 0a 0e  d2 36 cc 7f be 50 16 ef
// 00000040  06 04
//
// cf. correct field:
//   0  89: SEQUENCE {
//   2  19:   SEQUENCE {
//   4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
//  13   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
//        :     }
//  23  66:   BIT STRING
//        :     04 CE 30 31 6D 5A FD D3 53 2D 54 9A 27 54 D8 7C
//        :     D9 80 35 91 09 2D 6F 06 5A 8E E3 CB C0 01 B7 C9
//        :     13 5D 70 D4 E5 62 F2 1B 10 93 F7 D5 77 41 BA 9D
//        :     93 3E 18 3E 00 C6 0A 0E D2 36 CC 7F BE 50 16 EF
//        :     06
//        :   }
//
// as a short-term workaround, remove the trailing byte if:
//   - receiving an even number of bytes == 2*prime-coordinate +2 bytes
//   - starting byte is 04: uncompressed EC point
//   - trailing byte is 04: assume it belongs to the next OCTET STRING
//
// [mis-parsing encountered with v3.5.1, 2016-10-22]
//
// SoftHSM reports extra two bytes before the uncompressed point
// 0x04 || <Length*2+1>
//                 VV< Actual start of point
// 00000000  04 41 04 6c c8 57 32 13  02 12 6a 19 23 1d 5a 64  |.A.l.W2...j.#.Zd|
// 00000010  33 0c eb 75 4d e8 99 22  92 35 96 b2 39 58 14 1e  |3..uM..".5..9X..|
// 00000020  19 de ef 32 46 50 68 02  24 62 36 db ed b1 84 7b  |...2FPh.$b6....{|
// 00000030  93 d8 40 c3 d5 a6 b7 38  16 d2 35 0a 53 11 f9 51  |..@....8..5.S..Q|
// 00000040  fc a7 16                                          |...|
func (csp *impl) ecPoint(session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (ecpt, oid []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	}

	attr, err := csp.ctx.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get(EC point) [%s]", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_POINT {
			logger.Debugf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			// workarounds, see above
			if (0 == (len(a.Value) % 2)) &&
				(byte(0x04) == a.Value[0]) &&
				(byte(0x04) == a.Value[len(a.Value)-1]) {
				logger.Debugf("Detected opencryptoki bug, trimming trailing 0x04")
				ecpt = a.Value[0 : len(a.Value)-1] // Trim trailing 0x04
			} else if byte(0x04) == a.Value[0] && byte(0x04) == a.Value[2] {
				logger.Debugf("Detected SoftHSM bug, trimming leading 0x04 0xXX")
				ecpt = a.Value[2:len(a.Value)]
			} else {
				ecpt = a.Value
			}
		} else if a.Type == pkcs11.CKA_EC_PARAMS {
			logger.Debugf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			oid = a.Value
		}
	}
	if oid == nil || ecpt == nil {
		return nil, nil, fmt.Errorf("CKA_EC_POINT not found, perhaps not an EC Key?")
	}

	return ecpt, oid, nil
}

func (csp *impl) getSymKeyValue(session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (value []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	attr, err := csp.ctx.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, fmt.Errorf("PKCS11: get symetric key value [%s]", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_VALUE {
			value = a.Value
		}
	}

	if len(value) == 0 {
		return nil, fmt.Errorf("PKCS11: get symetric key value")
	}

	return
}

func (csp *impl) getKeyType(session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (cls uint, tp uint, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}

	attr, err := csp.ctx.GetAttributeValue(session, key, template)
	if err != nil {
		return 0, 0, fmt.Errorf("PKCS11: get(key class and type) [%s]", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_KEY_TYPE {
			dt, err := bytesToUint(a.Value)
			if err != nil {
				return 0, 0, fmt.Errorf("PKCS11: get(key type) [%s]", err)
			}
			tp = uint(dt)
		} else if a.Type == pkcs11.CKA_CLASS {
			var dt uint64
			dt, err := bytesToUint(a.Value)
			if err != nil {
				return 0, 0, fmt.Errorf("PKCS11: get(key class) [%s]", err)
			}
			cls = uint(dt)
		}
	}

	return
}

func (csp *impl) getGoCurve(session pkcs11.SessionHandle, keyObj pkcs11.ObjectHandle) (curve elliptic.Curve, x, y *big.Int, err error) {
	ecpt, marshaledOid, err := csp.ecPoint(session, keyObj)
	if err != nil {
		err = fmt.Errorf("Public key not found [%s]", err)
		return
	}

	curveOid := new(asn1.ObjectIdentifier)
	if _, err = asn1.Unmarshal(marshaledOid, curveOid); err != nil {
		err = fmt.Errorf("Failed Unmarshaling Curve OID [%s]\n%s", err.Error(), hex.EncodeToString(marshaledOid))
		return
	}

	if curve = namedCurveFromOID(*curveOid); curve == nil {
		err = fmt.Errorf("Cound not recognize Curve from OID")
		return
	}

	if x, y = elliptic.Unmarshal(curve, ecpt); x == nil {
		err = fmt.Errorf("Failed Unmarshaling Public Key")
		return
	}

	return
}

func (csp *impl) handleSessionReturn(err error, session pkcs11.SessionHandle) {
	if err != nil {
		if regex.MatchString(err.Error()) {
			logger.Infof("PKCS11 session invalidated, closing session: %v", err)
			csp.closeSession(session)
			return
		}
	}
	csp.returnSession(session)
}

func listAttrs(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) {
	var cktype, ckclass uint
	var ckaid, cklabel []byte

	if p11lib == nil {
		return
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckclass),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, cktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaid),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, cklabel),
	}

	// certain errors are tolerated, if value is missing
	attr, err := p11lib.GetAttributeValue(session, obj, template)
	if err != nil {
		logger.Debugf("P11: get(attrlist) [%s]\n", err)
	}

	for _, a := range attr {
		// Would be friendlier if the bindings provided a way convert Attribute hex to string
		logger.Debugf("ListAttr: type %d/0x%x, length %d\n%s", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))
	}
}

var (
	bigone  = new(big.Int).SetInt64(1)
	idCtr   = new(big.Int)
	idMutex sync.Mutex
)

func nextIDCtr() *big.Int {
	idMutex.Lock()
	idCtr = new(big.Int).Add(idCtr, bigone)
	idMutex.Unlock()
	return idCtr
}

func bytesToUint(bytes []byte) (data uint64, err error) {
	if len(bytes) == 0 {
		err = fmt.Errorf("empty byte array, failed to convert to uint64")
		return
	}

	data = *(*uint64)(unsafe.Pointer(&bytes[0]))
	return
}
