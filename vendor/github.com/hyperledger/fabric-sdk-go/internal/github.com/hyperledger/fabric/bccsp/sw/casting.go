package sw

import "crypto/ecdsa"

func ToECDSAPublicKey(pubKey *ecdsa.PublicKey) *ecdsaPublicKey {
	return &ecdsaPublicKey{pubKey: pubKey}
}
