package util

import (
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

func ToStdX509(certificate *x509.Certificate) *stdx509.Certificate {
	var cert1 x509.Certificate
	cert1 = *certificate
	cert := (*stdx509.Certificate)(unsafe.Pointer(&cert1))
	cert.CRLDistributionPoints = nil
	return cert
}

func ToFabricX509(certificate *stdx509.Certificate) *x509.Certificate {
	return (*x509.Certificate)(unsafe.Pointer(certificate))
}

func ToStdX509CertPool(certPool *x509.CertPool) *stdx509.CertPool {
	return (*stdx509.CertPool)(unsafe.Pointer(certPool))
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}
type mycertificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             mytbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}
type mytbsCertificateRequest struct {
	Raw       asn1.RawContent
	Version   int
	Subject   asn1.RawValue
	PublicKey publicKeyInfo
}

func X509ParseCertificateRequest(csrBytes []byte) (*x509.CertificateRequest, error) {
	var fixCsrBytes, tbsRow []byte
	csrv, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil && strings.Contains(err.Error(), "sequence truncated") {
		//对asn1格式不正确的情况进行补偿
		fixCsrBytes, tbsRow, err = changeCsr(csrBytes)
		if err != nil {
			return nil, err
		}
		csrv, err = x509.ParseCertificateRequest(fixCsrBytes)
		if err != nil {
			return nil, err
		}
		csrv.RawTBSCertificateRequest = tbsRow
	} else if err != nil {
		return nil, err
	}
	return csrv, nil
}
func changeCsr(asn1Data []byte) ([]byte, []byte, error) {
	var csr mycertificateRequest
	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, nil, err
	} else if len(rest) != 0 {
		return nil, nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	tbs := csr.TBSCSR.Raw
	csr1 := certificateRequest{
		TBSCSR: tbsCertificateRequest{
			Version:       csr.TBSCSR.Version,
			Subject:       csr.TBSCSR.Subject,
			PublicKey:     csr.TBSCSR.PublicKey,
			RawAttributes: nil,
		},
		SignatureAlgorithm: csr.SignatureAlgorithm,
		SignatureValue:     csr.SignatureValue,
	}

	csrByte, err := asn1.Marshal(csr1)
	if err != nil {
		return nil, nil, err
	}
	return csrByte, tbs, nil
}
