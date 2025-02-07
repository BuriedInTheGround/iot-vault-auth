package vault

import "golang.org/x/crypto/chacha20poly1305"

const NonceSize = chacha20poly1305.NonceSize

type Nonce []byte

func GenerateNonce() (Nonce, error) {
	return generateRand(NonceSize)
}
