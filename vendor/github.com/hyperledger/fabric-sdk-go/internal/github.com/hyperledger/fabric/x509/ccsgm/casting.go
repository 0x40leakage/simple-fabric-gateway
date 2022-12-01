package ccsgm

import (
	"math/big"
	"unsafe"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	commonX509 "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

func toGmCertPool(pool *commonX509.CertPool) *x509.CertPool {
	return (*x509.CertPool)(unsafe.Pointer(pool))
}

func toCommonCertPool(pool *x509.CertPool) *commonX509.CertPool {
	return (*commonX509.CertPool)(unsafe.Pointer(pool))
}

func toGmCert(cert *commonX509.Certificate) *x509.Certificate {
	return (*x509.Certificate)(unsafe.Pointer(cert))
}

func toCommonCert(cert *x509.Certificate) *commonX509.Certificate {
	return (*commonX509.Certificate)(unsafe.Pointer(cert))
}

func toGmCertRequest(certReq *commonX509.CertificateRequest) *x509.CertificateRequest {
	return (*x509.CertificateRequest)(unsafe.Pointer(certReq))
}

func toCommonCertRequest(certReq *x509.CertificateRequest) *commonX509.CertificateRequest {
	return (*commonX509.CertificateRequest)(unsafe.Pointer(certReq))
}

func toGmVerifyOpts(opts *commonX509.VerifyOptions) *x509.VerifyOptions {
	return (*x509.VerifyOptions)(unsafe.Pointer(opts))
}

func toCommonVerifyOpts(opts *x509.VerifyOptions) *commonX509.VerifyOptions {
	return (*commonX509.VerifyOptions)(unsafe.Pointer(opts))
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// todo: param: PreComputed
func toSm2PublicKey(pub *crypto.PublicKey) *sm2.PublicKey {
	if pub == nil {
		return nil
	}

	return &sm2.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
}

func toCryptoPublicKey(pub *sm2.PublicKey) *crypto.PublicKey {
	if pub == nil {
		return nil
	}

	return &crypto.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
}

func toSm2PrivateKey(priv *crypto.PrivateKey) *sm2.PrivateKey {
	if priv == nil {
		return nil
	}

	sm2Priv := &sm2.PrivateKey{
		PublicKey: sm2.PublicKey{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		},
		D: priv.D,
	}

	// param: DInv
	one := new(big.Int).SetInt64(1)
	sm2Priv.DInv = new(big.Int).Add(sm2Priv.D, one)
	sm2Priv.DInv.ModInverse(sm2Priv.DInv, sm2Priv.Curve.Params().N)

	// param: PreComputed    todo: unexported type, ignore it temporarily
	//if opt, ok := sm2Priv.Curve.(sm2.optMethod); ok {
	//	sm2Priv.PreComputed = opt.InitPubKeyTable(sm2Priv.PublicKey.X, sm2Priv.PublicKey.Y)
	//}

	return sm2Priv
}

func toCryptoPrivateKey(priv *sm2.PrivateKey) *crypto.PrivateKey {
	if priv == nil {
		return nil
	}

	return &crypto.PrivateKey{
		PublicKey: crypto.PublicKey{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		},
		D: priv.D,
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func toGmSignatureAlgorithm(algorithm commonX509.SignatureAlgorithm) x509.SignatureAlgorithm {
	return x509.SignatureAlgorithm(algorithm)
}

func toCommonSignatureAlgorithm(algorithm x509.SignatureAlgorithm) commonX509.SignatureAlgorithm {
	return commonX509.SignatureAlgorithm(algorithm)
}

func toGmPublicKeyAlgorithm(algorithm commonX509.PublicKeyAlgorithm) x509.PublicKeyAlgorithm {
	return x509.PublicKeyAlgorithm(algorithm)
}

func toCommonPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm) commonX509.PublicKeyAlgorithm {
	return commonX509.PublicKeyAlgorithm(algorithm)
}

func toGmKeyUsage(usage commonX509.KeyUsage) x509.KeyUsage {
	return x509.KeyUsage(usage)
}

func toCommonKeyUsage(usage x509.KeyUsage) commonX509.KeyUsage {
	return commonX509.KeyUsage(usage)
}

func toGmExtKeyUsage(extKeyUsage []commonX509.ExtKeyUsage) []x509.ExtKeyUsage {
	return *(*[]x509.ExtKeyUsage)(unsafe.Pointer(&extKeyUsage))
}

func toCommonExtKeyUsage(extKeyUsage []x509.ExtKeyUsage) []commonX509.ExtKeyUsage {
	return *(*[]commonX509.ExtKeyUsage)(unsafe.Pointer(&extKeyUsage))
}
