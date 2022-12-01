package transport

import (
	stdTLS "crypto/tls"
	stdX509 "crypto/x509"

	"github.com/Hyperledger-TWGC/ccs-gm/tls"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
)

func cloneConnectionState(origin *stdTLS.ConnectionState) (res *tls.ConnectionState) {
	res = &tls.ConnectionState{
		Version:                     origin.Version,
		HandshakeComplete:           origin.HandshakeComplete,
		DidResume:                   origin.DidResume,
		CipherSuite:                 origin.CipherSuite,
		NegotiatedProtocol:          origin.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  origin.NegotiatedProtocolIsMutual,
		ServerName:                  origin.ServerName,
		//PeerCertificates:            nil,
		//VerifiedChains:              nil,
		SignedCertificateTimestamps: origin.SignedCertificateTimestamps,
		OCSPResponse:                origin.OCSPResponse,
		TLSUnique:                   origin.TLSUnique,
	}

	for _,cert := range origin.PeerCertificates {
		res.PeerCertificates = append(res.PeerCertificates, cloneCertificate(cert))
	}

	res.VerifiedChains = make([][]*x509.Certificate, len(origin.VerifiedChains))
	for i, certs := range origin.VerifiedChains {
		for _, cert := range certs {
			res.VerifiedChains[i] = append(res.VerifiedChains[i], cloneCertificate(cert))
		}
	}

	return res
}

func cloneCertificate(origin *stdX509.Certificate) (res *x509.Certificate) {
	res = &x509.Certificate{
		Raw:                         origin.Raw,
		RawTBSCertificate:           origin.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     origin.RawSubjectPublicKeyInfo,
		RawSubject:                  origin.RawSubject,
		RawIssuer:                   origin.RawIssuer,
		Signature:                   origin.Signature,
		SignatureAlgorithm:          x509.SignatureAlgorithm(origin.SignatureAlgorithm),
		PublicKeyAlgorithm:          x509.PublicKeyAlgorithm(origin.PublicKeyAlgorithm),
		PublicKey:                   origin.PublicKey,
		Version:                     origin.Version,
		SerialNumber:                origin.SerialNumber,
		Issuer:                      origin.Issuer,
		Subject:                     origin.Subject,
		NotBefore:                   origin.NotBefore,
		NotAfter:                    origin.NotAfter,
		KeyUsage:                    x509.KeyUsage(origin.KeyUsage),
		Extensions:                  origin.Extensions,
		ExtraExtensions:             origin.ExtraExtensions,
		UnhandledCriticalExtensions: origin.UnhandledCriticalExtensions,
		//ExtKeyUsage:                 nil,
		UnknownExtKeyUsage:          origin.UnknownExtKeyUsage,
		BasicConstraintsValid:       origin.BasicConstraintsValid,
		IsCA:                        origin.IsCA,
		MaxPathLen:                  origin.MaxPathLen,
		MaxPathLenZero:              origin.MaxPathLenZero,
		SubjectKeyId:                origin.SubjectKeyId,
		AuthorityKeyId:              origin.AuthorityKeyId,
		OCSPServer:                  origin.OCSPServer,
		IssuingCertificateURL:       origin.IssuingCertificateURL,
		DNSNames:                    origin.DNSNames,
		EmailAddresses:              origin.EmailAddresses,
		IPAddresses:                 origin.IPAddresses,
		PermittedDNSDomainsCritical: origin.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         origin.PermittedDNSDomains,
		ExcludedDNSDomains:          origin.ExcludedDNSDomains,
		CRLDistributionPoints:       origin.CRLDistributionPoints,
		PolicyIdentifiers:           origin.PolicyIdentifiers,
	}

	for _,ku := range origin.ExtKeyUsage{
		res.ExtKeyUsage = append(res.ExtKeyUsage, x509.ExtKeyUsage(ku))
	}

	return res
}
