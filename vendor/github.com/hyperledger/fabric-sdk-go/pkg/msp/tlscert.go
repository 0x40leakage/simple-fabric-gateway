package msp

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/cryptogen/ca"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/cryptogen/csp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkinternal/cryptogen/msp"
)

func NewCA(baseDir, org, name, country, province, locality, orgUnit, streetAddress, postalCode, bccspType string) (*ca.CA, error) {
	return ca.NewCA(baseDir, org, name, country, province, locality, orgUnit, streetAddress, postalCode, bccspType)
}

func GenerateLocalTLS(baseDir, name string, sans []string, tlsCA *ca.CA, nodeType int, nodeOUs bool, bccspType string) (err error) {
	return msp.GenerateLocalTLS(baseDir, name, sans, tlsCA, nodeType, nodeOUs, bccspType)
}

func GetCAFromDir(baseDir, name, bccspType string) (*ca.CA, error) {
	_, priv, _ := csp.LoadPrivateKey(baseDir, bccspType)
	cert, _ := ca.LoadCertificateECDSA(baseDir)

	var country, province, locality, unit, address, code string

	if len(cert.Subject.Country) > 0 {
		country = cert.Subject.Country[0]
	}
	if len(cert.Subject.Province) > 0 {
		province = cert.Subject.Province[0]
	}
	if len(cert.Subject.Locality) > 0 {
		locality = cert.Subject.Locality[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		unit = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.StreetAddress) > 0 {
		address = cert.Subject.StreetAddress[0]
	}
	if len(cert.Subject.PostalCode) > 0 {
		code = cert.Subject.PostalCode[0]
	}

	return &ca.CA{
		Name:               name,
		Signer:             priv,
		SignCert:           cert,
		Country:            country,
		Province:           province,
		Locality:           locality,
		OrganizationalUnit: unit,
		StreetAddress:      address,
		PostalCode:         code,
	}, nil
}
