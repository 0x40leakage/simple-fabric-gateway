package sw

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/ccsgm"
)

type sm4Encryptor struct{}

func (e *sm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	switch key := k.(type) {
	case *sm4PrivateKey:
		if key.key == nil {
			return nil, errors.New("invalid sm4PrivateKey Key, mustn't be nil")
		}
		return ccsgm.NewSm4().Encrypt(key.key, plaintext, opts)
	default:
		return nil, fmt.Errorf("key not recognized [%s]", opts)
	}
}

type sm4Decryptor struct{}

func (*sm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	switch key := k.(type) {
	case *sm4PrivateKey:
		if key.key == nil {
			return nil, errors.New("invalid sm4PrivateKey Key. Mustn't be nil")
		}
		return ccsgm.NewSm4().Decrypt(key.key, ciphertext, opts)
	default:
		return nil, fmt.Errorf("key not recognized [%s]", opts)
	}
}
