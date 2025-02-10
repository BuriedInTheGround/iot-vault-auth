package vault

const NonceSize = 12

type Nonce []byte

func GenerateNonce() (Nonce, error) {
	return generateRand(NonceSize)
}
