package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NumberOfKeys    = 8
	ChallengeSize   = 6
	KeySize         = chacha20poly1305.KeySize
	SessionKeySize  = chacha20poly1305.KeySize
	SessionDuration = 30 * time.Second
)

func init() {
	if ChallengeSize > NumberOfKeys {
		panic("ChallengeSize cannot be greater than NumberOfKeys")
	}
	if SessionKeySize != KeySize {
		panic("SessionKeySize must be equal to KeySize")
	}
}

type Vault []byte

func GenerateVault() (Vault, error) {
	vault, err := generateRand(NumberOfKeys * KeySize)
	if err != nil {
		return nil, err
	}
	return vault, nil
}

func NewVaultFromFile(name string) (Vault, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	vault, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(vault) != NumberOfKeys*KeySize {
		return nil, fmt.Errorf("wrong size")
	}
	return vault, nil
}

func (v Vault) Key(i int) []byte {
	return v[i*KeySize : (i+1)*KeySize]
}

func (v Vault) GenerateChallenge() (encodedIndexes []byte, err error) {
	indexes := make([]int, 0, ChallengeSize)
	for len(indexes) < ChallengeSize {
		n, err := rand.Int(rand.Reader, big.NewInt(NumberOfKeys))
		if err != nil {
			return nil, fmt.Errorf("failed to obtain randomness: %w", err)
		}
		i := int(n.Int64())
		if !slices.Contains(indexes, i) {
			indexes = append(indexes, i)
		}
	}
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(&indexes); err != nil {
		return nil, fmt.Errorf("failed to encode indexes: %w", err)
	}
	return buf.Bytes(), nil
}

func (v Vault) ComputeChallengeKey(encodedIndexes []byte) (Key, error) {
	dec := gob.NewDecoder(bytes.NewReader(encodedIndexes))
	indexes := make([]int, ChallengeSize)
	if err := dec.Decode(&indexes); err != nil {
		return nil, fmt.Errorf("failed to decode indexes: %w", err)
	}
	key := make([]byte, KeySize)
	for _, i := range indexes {
		subtle.XORBytes(key, key, v.Key(i))
	}
	return key, nil
}

func (v Vault) Rotate(key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("key is too short, cannot provide enough security")
	}

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(v); err != nil {
		return err
	}
	h := mac.Sum(nil)
	k := len(h)

	// Work on a copy of the vault for padding
	old := make(Vault, len(v))
	copy(old, v)

	// Pad with zeros if needed
	if rem := len(old) % k; rem != 0 {
		old = append(old, bytes.Repeat([]byte{0}, k-rem)...)
	}

	j := len(old) / k
	for i := range j {
		n := make([]byte, k)
		big.NewInt(int64(i + 1)).FillBytes(n)
		subtle.XORBytes(v[i*k:], old[i*k:], h)
		subtle.XORBytes(v[i*k:], v[i*k:], n)
	}
	return nil
}

func (v Vault) WriteTo(w io.Writer) (n int64, err error) {
	m, err := w.Write(v)
	return int64(m), err
}

func generateRand(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to obtain randomness: %w", err)
	}
	return b, nil
}
