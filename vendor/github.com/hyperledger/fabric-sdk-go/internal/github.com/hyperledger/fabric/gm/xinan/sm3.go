package xinan

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
)

type SM3 struct {
	xinanctx *ctx
}

func (s *SM3) Hash(msg []byte) ([]byte, error) {
	return s.xinanctx.sm3Hash(msg)
}

func NewSm3(s *HSMServer) gm.Sm3 {
	return &SM3{xinanctx: s.xinanctx}
}
