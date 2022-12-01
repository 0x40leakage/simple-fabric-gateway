package ccsgm

import (
	"errors"

	"github.com/Hyperledger-TWGC/ccs-gm/sm3"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
)

type SM3 struct{}

func NewSm3() gm.Sm3 {
	return &SM3{}
}

func (SM3) Hash(msg []byte) ([]byte, error) {
	hasher := sm3.New()
	if hasher == nil {
		return nil, errors.New("the hasher is nil")
	}

	hasher.Write(msg)
	digest := hasher.Sum(nil)
	return digest, nil
}
