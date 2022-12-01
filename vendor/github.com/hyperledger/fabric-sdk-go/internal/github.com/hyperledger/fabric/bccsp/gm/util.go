package gm

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// 信安加密机返回的csr竟然解析会报asn1错误，手动解析

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type tbsCertificateRequest struct {
	Raw       asn1.RawContent
	Version   int
	Subject   asn1.RawValue
	PublicKey publicKeyInfo
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func parseDN(asn1Data []byte) (string, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return "", err
	} else if len(rest) != 0 {
		return "", asn1.SyntaxError{Msg: "trailing data"}
	}

	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(csr.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return "", err
	} else if len(rest) != 0 {
		return "", errors.New("x509: trailing data after X.509 Subject")
	}
	var ret pkix.Name
	ret.FillFromRDNSequence(&subject)
	return ret.String(), nil
}
