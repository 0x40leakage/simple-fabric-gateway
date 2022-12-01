package util

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/pem"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"io"
	"unsafe"

	ccsSM2 "github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/pkg/errors"
)

type XinanSigner struct {
	b         core.CryptoSuite
	k         core.Key
	publicKey crypto.PublicKey
}

func NewXinanSigner(csp core.CryptoSuite, key core.Key) (*XinanSigner, error) {
	csrBytes, err := key.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "key Bytes")
	}
	p, _ := pem.Decode(csrBytes)
	csr, err := util.X509ParseCertificateRequest(p.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "util x509ParseCertificateRequest")
	}
	var publibKey *crypto.PublicKey
	switch csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		publibKey = (*crypto.PublicKey)(unsafe.Pointer(csr.PublicKey.(*ecdsa.PublicKey)))
	case *ccsSM2.PublicKey:
		publibKey = (*crypto.PublicKey)(unsafe.Pointer(csr.PublicKey.(*ccsSM2.PublicKey)))
	}
	return &XinanSigner{b: csp, k: key, publicKey: publibKey}, nil
}

func (signer *XinanSigner) Public() crypto.PublicKey {
	return signer.publicKey
}
func (signer *XinanSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signer.b.Sign(signer.k, digest, opts)
}

func (signer *XinanSigner) GetCSR() ([]byte, error) {
	return signer.k.Bytes()
}
