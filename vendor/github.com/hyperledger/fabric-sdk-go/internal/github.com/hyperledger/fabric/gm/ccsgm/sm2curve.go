package ccsgm

import (
	"crypto/elliptic"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
)

type SM2Curve struct{}

func NewSm2Curve() gm.Sm2Curve {
	return &SM2Curve{}
}

func (c *SM2Curve) P256Sm2() elliptic.Curve {
	return sm2.P256()
}
