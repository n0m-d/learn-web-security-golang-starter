package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	nonceLength             = 12
	authenticationTagLength = 16
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	return encrypt(plaintext, key, rand.Reader)
}

func encrypt(plaintext []byte, key [32]byte, randomSource io.Reader) (EncryptedPayload, error) {
	blockCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create encryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("create authenticated encryption: %w", err)
	}
	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(randomSource, nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("generate encryption nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[len(sealed)-authenticationTagLength:],
		Ciphertext: sealed[:len(sealed)-authenticationTagLength],
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != nonceLength || len(payload.AuthTag) != authenticationTagLength {
		return nil, errors.New("invalid encrypted payload")
	}
	blockCipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create decryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, fmt.Errorf("create authenticated decryption: %w", err)
	}
	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)
	plaintext, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, errors.New("encrypted payload failed authentication")
	}
	return plaintext, nil
}
