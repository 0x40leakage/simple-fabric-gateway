package sdf

/*
#include "sdf.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Error represents an SDF error.
type Error int

func (e Error) Error() string {
	return fmt.Sprintf("sdf: 0x%X: %s", int(e), strerror[int(e)])
}

type DeviceInfo struct {
	IssuerName      string
	DeviceName      string
	DeviceSerial    string
	DeviceVersion   uint
	StandardVersion uint
	AsymAlgAbility  [2]uint
	SymAlgAbility   uint
	HashAlgAbility  uint
	BufferSize      uint
	Dmkcv           [2]uint
}

type RSAPublicKey struct {
	Bits uint
	M    [RSAref_MAX_LEN]byte
	E    [RSAref_MAX_LEN]byte
}

func CRSAPublicKeyToGo(pubKey *C.RSArefPublicKey) *RSAPublicKey {
	pub := RSAPublicKey{
		Bits: uint(pubKey.bits),
	}
	m := C.GoBytes(unsafe.Pointer(&pubKey.m[0]), RSAref_MAX_LEN)
	e := C.GoBytes(unsafe.Pointer(&pubKey.e[0]), RSAref_MAX_LEN)
	copy(pub.M[:], m)
	copy(pub.E[:], e)
	return &pub
}

type RSAPrivateKey struct {
	RSAPublicKey
	D     [RSAref_MAX_LEN]byte // private exponent
	Prime [2][RSAref_MAX_LEN]byte
	PExp  [2][RSAref_MAX_LEN]byte
	Coef  [RSAref_MAX_LEN]byte
}

func CRSAPrivateKeyToGo(privKey *C.RSArefPrivateKey) *RSAPrivateKey {
	pub := RSAPublicKey{
		Bits: uint(privKey.bits),
	}
	m := C.GoBytes(unsafe.Pointer(&privKey.m[0]), RSAref_MAX_LEN)
	e := C.GoBytes(unsafe.Pointer(&privKey.e[0]), RSAref_MAX_LEN)
	copy(pub.M[:], m)
	copy(pub.E[:], e)
	priv := RSAPrivateKey{
		RSAPublicKey: pub,
	}
	d := C.GoBytes(unsafe.Pointer(&privKey.d[0]), RSAref_MAX_LEN)
	coef := C.GoBytes(unsafe.Pointer(&privKey.coef[0]), RSAref_MAX_LEN)
	prime0 := C.GoBytes(unsafe.Pointer(&privKey.prime[0][0]), RSAref_MAX_LEN)
	prime1 := C.GoBytes(unsafe.Pointer(&privKey.prime[1][0]), RSAref_MAX_LEN)
	pexp0 := C.GoBytes(unsafe.Pointer(&privKey.pexp[0][0]), RSAref_MAX_LEN)
	pexp1 := C.GoBytes(unsafe.Pointer(&privKey.pexp[1][0]), RSAref_MAX_LEN)
	copy(priv.D[:], d)
	copy(priv.Coef[:], coef)
	copy(priv.Prime[0][:], prime0)
	copy(priv.Prime[1][:], prime1)
	copy(priv.PExp[0][:], pexp0)
	copy(priv.PExp[1][:], pexp1)

	return &priv
}

type ECCCipher struct {
	X [ECCref_MAX_LEN]byte
	Y [ECCref_MAX_LEN]byte
	M [32]byte
	L uint
	C [ECC_CIPHER_MAX]byte
}

func CECCCipherToGo(cipher *C.ECCCipher) *ECCCipher {
	ecc := new(ECCCipher)
	copy(ecc.X[:], C.GoBytes(unsafe.Pointer(&cipher.x[0]), ECCref_MAX_LEN))
	copy(ecc.Y[:], C.GoBytes(unsafe.Pointer(&cipher.y[0]), ECCref_MAX_LEN))
	copy(ecc.M[:], C.GoBytes(unsafe.Pointer(&cipher.M[0]), 32))
	ecc.L = uint(cipher.L)
	copy(ecc.C[:], C.GoBytes(unsafe.Pointer(&cipher.C[0]), ECC_CIPHER_MAX))
	return ecc
}

type ECCPublicKey struct {
	Bits uint
	X    [ECCref_MAX_LEN]byte
	Y    [ECCref_MAX_LEN]byte
}

type ECCPrivateKey struct {
	Bits uint
	D    [ECCref_MAX_LEN]byte
}

func CECCPublicKeyToGo(pub *C.ECCrefPublicKey) *ECCPublicKey {
	var pubKey ECCPublicKey
	pubKey.Bits = uint(pub.bits)
	copy(pubKey.X[:], C.GoBytes(unsafe.Pointer(&pub.x[0]), ECCref_MAX_LEN))
	copy(pubKey.Y[:], C.GoBytes(unsafe.Pointer(&pub.y[0]), ECCref_MAX_LEN))
	return &pubKey
}

func CECCPrivateKeyToGo(priv *C.ECCrefPrivateKey) *ECCPrivateKey {
	var privKey ECCPrivateKey
	privKey.Bits = uint(priv.bits)
	copy(privKey.D[:], C.GoBytes(unsafe.Pointer(&priv.D[0]), ECCref_MAX_LEN))
	return &privKey
}

type Agreement struct {
	AgreementCode     uint
	ISKIndex          uint
	KeyBits           uint
	SponsorIDLength   uint
	SelfID            []byte
	SelfTmpPublicKey  *ECCPublicKey
	SelfTmpPrivateKey *ECCPrivateKey
}

// stubData is a persistent nonempty byte array used by cMessage.
var stubData = []byte{0}

// cMessage returns the pointer/length pair corresponding to data.
func cMessage(data []byte) *C.uchar {
	l := len(data)
	if l == 0 {
		// &data[0] is forbidden in this case, so use a nontrivial array instead.
		data = stubData
	}
	return (*C.uchar)(unsafe.Pointer(&data[0]))
}
