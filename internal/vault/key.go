package vault

import (
	"crypto/aes"
	"crypto/cipher"
)

type Key []byte

func (k Key) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
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
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
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
