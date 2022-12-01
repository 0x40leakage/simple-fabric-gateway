package xinan

import (
	gocrypto "crypto"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/x509"
)

type SM2 struct {
	server *HSMServer
}

type AsymmetricCipher struct {
	X *big.Int
	Y *big.Int
	M []byte
	C []byte
}

func NewSm2(s *HSMServer) gm.Sm2 {
	return &SM2{server: s}
}

func (s *SM2) UploadCertIfNotExist(cert *x509.Certificate) error {
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.uploadCert(sockFd, cert.Subject.String(), cert.Raw)
}

// xinan generateKey will return csr bytes
func (s *SM2) GenerateKey(opts ...interface{}) (interface{}, error) {
	var dn, keyID string
	if len(opts) >= 2 {
		if opt, ok := opts[0].(string); ok {
			dn = opt
		}
		if opt, ok := opts[1].(string); ok {
			keyID = opt
		}
	}
	if len(dn) == 0 || dn == "" || len(keyID) == 0 || keyID == "" {
		return nil, fmt.Errorf("dn and alias must not be nil")
	}

	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.iNS_KPLGenP10Req(sockFd, dn, keyID)
}

// 注意该接口导入的证书，证书格式是base64编码
func (s *SM2) ImportCert(opts ...interface{}) error {
	var keyID string
	var cert []byte
	if len(opts) >= 2 {
		if opt, ok := opts[0].(string); ok {
			keyID = opt
		}
		if opt, ok := opts[1].([]byte); ok {
			cert = opt
		}
	}
	if len(keyID) == 0 || keyID == "" || cert == nil || len(cert) == 0 {
		return fmt.Errorf("keyID and cert must not be nil")
	}
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.iNS_KPLImportCert(sockFd, keyID, cert)
}

func (s *SM2) Sign(priv interface{}, rand io.Reader, digest []byte, opts gocrypto.SignerOpts) ([]byte, error) {
	dn, ok := priv.(string)
	if !ok {
		return nil, fmt.Errorf("priv key is not string")
	}
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	dig, err := s.server.xinanctx.signWithServer(sockFd, dn, digest)
	digg := asn1Bytes(dig)
	return digg, err
}

func (s *SM2) Verify(pub interface{}, digest []byte, sign []byte) bool {
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return false
	}
	sign1 := signatureBytesForXinan(sign)
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	switch pub.(type) {
	case []byte:
		return s.server.xinanctx.verifyWithCertServer(sockFd, pub.([]byte), digest, sign1)
	case string:
		return s.server.xinanctx.verifyWithServer(sockFd, pub.(string), digest, sign1)
	}
	logger.Errorf("xinan verify error, the pub should be cert bytes or dn")
	return false
}

//对msg进行非对称加密，信安世纪加密机生成ASN1格式密文，
//解密后以0x04 + []byte(X) + []byte(Y) + []byte(Hash) + []byte(Encrydata)格式对密文进行序列化返回
//之前ccsgm插件就是这个格式的，所以在这里也使用同样的格式
func (s *SM2) Encrypt(pub interface{}, plaintext []byte) ([]byte, error) {
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	var ciphertext []byte
	switch pub.(type) {
	case []byte:
		ciphertext, err = s.server.xinanctx.sm2EncryptWithCert(sockFd, pub.([]byte), plaintext)
		if err != nil {
			return nil, err
		}
	case string:
		ciphertext, err = s.server.xinanctx.sm2Encrypt(sockFd, pub.(string), plaintext)
		if err != nil {
			return nil, err
		}
	}

	if ciphertext == nil || len(ciphertext) == 0 {
		logger.Errorf("xinan sm2 encrypt error, the pub should be cert bytes or dn")
		return nil, fmt.Errorf("xinan sm2 encrypt error, the pub should be cert bytes or dn")
	}
	ac := &AsymmetricCipher{}
	if _, err := asn1UnmarshalWithCheck(ciphertext, ac); err != nil {
		return nil, fmt.Errorf("asn1 unmarshal error: %w", err)
	}

	cipherDer := make([]byte, 96+len(ac.C))
	copy(cipherDer[32-len(ac.X.Bytes()):], ac.X.Bytes())
	copy(cipherDer[64-len(ac.Y.Bytes()):], ac.Y.Bytes())
	copy(cipherDer[64:], ac.M)
	copy(cipherDer[96:], ac.C)
	cipherDer = append([]byte{0x04}, cipherDer...)

	return cipherDer, nil
}

//按照0x04 + []byte(X) + []byte(Y) + []byte(Hash) + []byte(Encrydata)格式对密文进行反序列化成ASN1格式，
//使用信安世纪加密机进行解密
func (s *SM2) Decrypt(priv interface{}, cipherDer []byte) ([]byte, error) {
	dn, ok := priv.(string)
	if !ok {
		logger.Errorf("sm2 decrypt,the priv is not string", priv)
		return nil, fmt.Errorf("sm2 decrypt,the priv is not string:%v", priv)
	}
	cipherDer = cipherDer[1:] // drop 0x04
	ac := AsymmetricCipher{
		X: new(big.Int).SetBytes(cipherDer[:32]),
		Y: new(big.Int).SetBytes(cipherDer[32:64]),
		M: cipherDer[64:96],
		C: cipherDer[96:],
	}

	var ciphertext []byte
	ciphertext, err := asn1.Marshal(ac)
	if err != nil {
		return nil, fmt.Errorf("Failed to asn1-mashal into DER-encoded CipherText [%s]", err)
	}
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.sm2Decrypt(sockFd, dn, ciphertext)
}
