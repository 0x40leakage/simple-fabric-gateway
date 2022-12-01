package ccsgm

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	cryptoX509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"
	"time"
	"unsafe"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/Hyperledger-TWGC/ccs-gm/utils"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	commonX509 "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

var logger = flogging.MustGetLogger("ccsgm.x509")

type X509 struct {
}

func NewX509() *X509 {
	return &X509{}
}

func (gmX509 *X509) Name() string {
	return "CCSGM Cert Plugin"
}

func (gmX509 *X509) NewCertPool() *commonX509.CertPool {
	pool := x509.NewCertPool()
	return toCommonCertPool(pool)
}

func (gmX509 *X509) CreateCertificate(rand io.Reader, template, parent *commonX509.Certificate, pub, priv interface{}) (cert []byte, err error) {
	tem, par := toGmCert(template), toGmCert(parent)
	switch pub.(type) {
	case *crypto.PublicKey:
		pubkey := toSm2PublicKey(pub.(*crypto.PublicKey))
		return x509.CreateCertificate(rand, tem, par, pubkey, newSm2Signer(priv.(gocrypto.Signer)))
	default:
		return x509.CreateCertificate(rand, tem, par, pub, newSm2Signer(priv.(gocrypto.Signer)))
	}
}

func (gmX509 *X509) CreateCertificateRequest(rand io.Reader, template *commonX509.CertificateRequest, priv interface{}) (cert []byte, err error) {
	tem := toGmCertRequest(template)
	return x509.CreateCertificateRequest(rand, tem, newSm2Signer(priv.(gocrypto.Signer)))
}

func (gmX509 *X509) ParseCertificate(asn1Data []byte) (*commonX509.Certificate, error) {
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		logger.Errorf("failed to parse certificate. err: %v", err)
		return nil, err
	}
	return toCommonCert(cert), nil
}

func (gmX509 *X509) ParseCertificates(asn1Data []byte) ([]*commonX509.Certificate, error) {
	certs, err := x509.ParseCertificates(asn1Data)
	if err != nil {
		logger.Errorf("failed to parse certificate. err: %v", err)
		return nil, err
	}

	certsList := make([]*commonX509.Certificate, 0, len(certs))
	for _, cert := range certs {
		certsList = append(certsList, toCommonCert(cert))
	}
	return certsList, nil
}

func (gmX509 *X509) ParseCertificateRequest(asn1Data []byte) (*commonX509.CertificateRequest, error) {
	certReq, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, err
	}
	return toCommonCertRequest(certReq), err
}

func (gmX509 *X509) ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	certList, err := x509.ParseCRL(crlBytes)
	if err != nil {
		logger.Errorf("failed to parse certificate revocation list. err: %v", err)
		return nil, err
	}
	return certList, err
}

// MarshalECPrivateKey 把椭圆曲线私钥转换为PCKS8标准，DER格式
func (gmX509 *X509) MarshalECPrivateKey(key *crypto.PrivateKey) (der []byte, err error) {
	switch key.Curve {
	case sm2.P256():
		return x509.MarshalECPrivateKey(toSm2PrivateKey(key))
	}
	return x509.MarshalECPrivateKey((*ecdsa.PrivateKey)(unsafe.Pointer(key)))
}

func (gmX509 *X509) ParseECPrivateKey(der []byte) (*crypto.PrivateKey, error) {
	privKey, err := x509.ParseECPrivateKey(der)
	if err != nil {
		logger.Debugf("failed to parse EC privateKey. err: %v", err)
		return nil, err
	}

	switch privKey.(type) {
	case *sm2.PrivateKey:
		return toCryptoPrivateKey(privKey.(*sm2.PrivateKey)), nil
	case *ecdsa.PrivateKey:
		return (*crypto.PrivateKey)(unsafe.Pointer(privKey.(*ecdsa.PrivateKey))), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", reflect.TypeOf(privKey))
	}
}

// MarshalPKIXPublicKey 把椭圆曲线公钥转换为PKIX标准，DER格式
func (gmX509 *X509) MarshalPKIXPublicKey(pub interface{}) (der []byte, err error) {
	switch pub.(type) {
	case *crypto.PublicKey:
		switch pub.(*crypto.PublicKey).Curve {
		case sm2.P256():
			return x509.MarshalPKIXPublicKey(toSm2PublicKey(pub.(*crypto.PublicKey)))
		default:
			return x509.MarshalPKIXPublicKey((*ecdsa.PublicKey)(pub.(*crypto.PublicKey)))
		}
	}
	return x509.MarshalPKIXPublicKey(pub)
}

func (gmX509 *X509) ParsePKIXPublicKey(derBytes []byte) (interface{}, error) {
	pubKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		logger.Errorf("failed to parse PKIX publicKey. err: %v", err)
		return nil, err
	}

	switch pubKey.(type) {
	case *sm2.PublicKey:
		return toCryptoPublicKey(pubKey.(*sm2.PublicKey)), nil
	}
	return pubKey, nil
}

// ParsePKCS8PrivateKey 把PCKS8标准DER格式的数据转换为椭圆曲线私钥
func (gmX509 *X509) ParsePKCS8PrivateKey(der []byte) (interface{}, error) {
	privKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		logger.Debugf("failed to parse PKCS8 privateKey. err: %v", err)
		return nil, err
	}

	switch privKey.(type) {
	case *sm2.PrivateKey:
		return toCryptoPrivateKey(privKey.(*sm2.PrivateKey)), nil
	}
	return privKey, nil
}

func (gmX509 *X509) MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

func (gmX509 *X509) ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

func (gmX509 *X509) IsEncryptedPEMBlock(b *pem.Block) bool {
	return x509.IsEncryptedPEMBlock(b)
}

func (gmX509 *X509) EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg cryptoX509.PEMCipher) (*pem.Block, error) {
	return x509.EncryptPEMBlock(rand, blockType, data, password, x509.PEMCipher(alg))
}

func (gmX509 *X509) DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	return x509.DecryptPEMBlock(b, password)
}

// PrivateKeyToEncryptedPEMBytes 把私钥转换为加密的PEM格式
func (gmX509 *X509) PrivateKeyToEncryptedPEMBytes(privateKey interface{}, pwd []byte) (pemBytes []byte, err error) {
	key, ok := privateKey.(*crypto.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %v, only for *crypto.PrivateKey", reflect.TypeOf(key))
	}
	return utils.PrivateKeyToPEM(toSm2PrivateKey(key), pwd)
}

// PublicKeyToEncryptedPEMBytes 把公钥转换为加密的PEM格式
func (gmX509 *X509) PublicKeyToEncryptedPEMBytes(publicKey interface{}, pwd []byte) ([]byte, error) {
	key, ok := publicKey.(*crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %v, only for *crypto.PublicKey", reflect.TypeOf(key))
	}
	return utils.PublicKeyToPEM(toSm2PublicKey(key), pwd)
}

// PEMBytesToPrivateKey 把PEM数据转换为私钥
func (gmX509 *X509) PEMBytesToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	key, err := utils.PEMtoPrivateKey(raw, pwd)
	if err != nil {
		logger.Errorf("failed to read privateKey from mem. err: %v", err)
		return nil, err
	}
	return toCryptoPrivateKey(key), nil
}

// PEMBytesToPublicKey 把PME数据转换为公钥
func (gmX509 *X509) PEMBytesToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	key, err := utils.PEMtoPublicKey(raw, pwd)
	if err != nil {
		logger.Errorf("failed to read publicKey from mem. err: %v", err)
		return nil, err
	}
	return toCryptoPublicKey(key), nil
}

// 	CertCheckCRLSignature Certificate wrapper方法
func (gmX509 *X509) CertCheckCRLSignature(certificate *commonX509.Certificate, crl *pkix.CertificateList) error {
	cert := toGmCert(certificate)
	return cert.CheckCRLSignature(crl)
}

func (gmX509 *X509) CertCheckSignature(certificate *commonX509.Certificate, algo commonX509.SignatureAlgorithm, signed, signature []byte) error {
	cert := toGmCert(certificate)
	algorithm := toGmSignatureAlgorithm(algo)
	return cert.CheckSignature(algorithm, signed, signature)
}

func (gmX509 *X509) CertCheckSignatureFrom(certificate *commonX509.Certificate, parent *commonX509.Certificate) error {
	cert := toGmCert(certificate)
	parentCert := toGmCert(parent)
	return cert.CheckSignatureFrom(parentCert)
}

func (gmX509 *X509) CertCreateCRL(certificate *commonX509.Certificate, rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	cert := toGmCert(certificate)
	switch priv.(type) {
	case *crypto.PrivateKey:
		priv = toSm2PrivateKey(priv.(*crypto.PrivateKey))
	case gocrypto.Signer:
		priv = newSm2Signer(priv.(gocrypto.Signer))
	}
	return cert.CreateCRL(rand, priv, revokedCerts, now, expiry)
}

func (gmX509 *X509) CertEqual(certificate *commonX509.Certificate, otherCertificate *commonX509.Certificate) bool {
	cert := toGmCert(certificate)
	other := toGmCert(otherCertificate)
	return cert.Equal(other)
}

func (gmX509 *X509) CertVerify(certificate *commonX509.Certificate, opts commonX509.VerifyOptions) (chains [][]*commonX509.Certificate, err error) {
	cert := toGmCert(certificate)
	options := toGmVerifyOpts(&opts)
	gmChains, err := cert.Verify(*options)
	if err != nil {
		logger.Errorf("failed to verify options. err: %v", err)
		return nil, err
	}

	var row = len(gmChains)
	if row == 0 {
		return nil, nil
	}

	var col = len(gmChains[0])
	chains = make([][]*commonX509.Certificate, row)
	for i := 0; i < row; i++ {
		chains[i] = make([]*commonX509.Certificate, col)
		for j := 0; j < col; j++ {
			chains[i][j] = toCommonCert(gmChains[i][j])
		}
	}
	return chains, err
}

func (gmX509 *X509) CertVerifyHostname(certificate *commonX509.Certificate, h string) error {
	cert := toGmCert(certificate)
	return cert.VerifyHostname(h)
}

// 	CertPoolAddCert CertPool wrapper方法
func (gmX509 *X509) CertPoolAddCert(certPool *commonX509.CertPool, certificate *commonX509.Certificate) {
	pool := toGmCertPool(certPool)
	cert := toGmCert(certificate)
	pool.AddCert(cert)
}

func (gmX509 *X509) CertPoolAppendCertsFromPEM(certPool *commonX509.CertPool, pemCerts []byte) (ok bool) {
	pool := toGmCertPool(certPool)
	return pool.AppendCertsFromPEM(pemCerts)
}

func (gmX509 *X509) CertPoolSubjects(certPool *commonX509.CertPool) [][]byte {
	pool := toGmCertPool(certPool)
	return pool.Subjects()
}

func (gmX509 *X509) CheckSignature(request *commonX509.CertificateRequest) error {
	sm2Req := toGmCertRequest(request)
	return sm2Req.CheckSignature()
}
