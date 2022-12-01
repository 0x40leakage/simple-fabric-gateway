package ccsgm

import (
	"math/big"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
)

var logger = flogging.MustGetLogger("gm.ccsgm")

func toCryptoPrivateKey(priv *sm2.PrivateKey) *crypto.PrivateKey {
	if priv == nil {
		return nil
	}

	return &crypto.PrivateKey{
		PublicKey: crypto.PublicKey{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		},
		D: priv.D,
	}
}

func toCryptoPublicKey(pub *sm2.PublicKey) *crypto.PublicKey {
	if pub == nil {
		return nil
	}

	return &crypto.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
}

func toSm2PrivateKey(priv *crypto.PrivateKey) *sm2.PrivateKey {
	if priv == nil {
		return nil
	}

	sm2Priv := &sm2.PrivateKey{
		PublicKey: sm2.PublicKey{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		},
		D: priv.D,
	}

	// param: DInv
	one := new(big.Int).SetInt64(1)
	sm2Priv.DInv = new(big.Int).Add(sm2Priv.D, one)
	sm2Priv.DInv.ModInverse(sm2Priv.DInv, sm2Priv.Curve.Params().N)

	// param: PreComputed    todo: unexported type, ignore it temporarily
	//if opt, ok := sm2Priv.Curve.(sm2.optMethod); ok {
	//	sm2Priv.PreComputed = opt.InitPubKeyTable(sm2Priv.PublicKey.X, sm2Priv.PublicKey.Y)
	//}

	return sm2Priv
}

// todo: param: PreComputed
func toSm2PublicKey(pub *crypto.PublicKey) *sm2.PublicKey {
	if pub == nil {
		return nil
	}

	return &sm2.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
}
