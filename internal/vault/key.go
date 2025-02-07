package vault

import "golang.org/x/crypto/chacha20poly1305"

type Key []byte

func (k Key) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}
	nonce, err := generateRand(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return append(nonce, ciphertext...), nil
}

func (k Key) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

type SessionKey = Key

func GenerateSessionKey() (SessionKey, error) {
	return generateRand(SessionKeySize)
}
