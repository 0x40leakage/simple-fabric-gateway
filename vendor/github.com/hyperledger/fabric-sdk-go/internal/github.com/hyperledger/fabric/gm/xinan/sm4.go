package xinan

import (
	"errors"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
)

type SM4 struct {
	server *HSMServer
}

func NewSm4(s *HSMServer) gm.Sm4 {
	return &SM4{server: s}
}

func (s *SM4) GenerateKey() ([]byte, error) {
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.generateSessionKey(sockFd)
}

//SM4 CBC
func (s *SM4) Encrypt(key, src []byte, opts ...interface{}) ([]byte, error) {
	var isKeyID bool
	if len(opts) > 0 {
		if opt, ok := opts[0].(bool); ok {
			isKeyID = opt
		}
	}
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.sm4Encrypt(sockFd, key, src, isKeyID)
}

func (s *SM4) Decrypt(key []byte, ciphertext []byte, opts ...interface{}) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, errors.New("ciphertext is wrong")
	}
	var isKeyID bool
	if len(opts) > 0 {
		if opt, ok := opts[0].(bool); ok {
			isKeyID = opt
		}
	}
	sockFd, err := s.server.getSockFd()
	if err != nil {
		return nil, err
	}
	defer func() { s.server.handleSockFdReturn(err, sockFd) }()
	return s.server.xinanctx.sm4Decrypt(sockFd, key, ciphertext, isKeyID)
}
