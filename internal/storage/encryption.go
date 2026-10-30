package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"slices"
)

type EncryptedPayload struct {
	AuthTag    []byte
	Ciphertext []byte
	Nonce      []byte
}

func getAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	aead, err := getAEAD(key)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	authTag, ciphertext := sealed[len(sealed)-16:], sealed[:len(sealed)-16]
	result := EncryptedPayload{
		AuthTag:    authTag,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}
	return result, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.AuthTag) != 16 || len(payload.Nonce) != 12 {
		return nil, fmt.Errorf("Invalid Encrypted Payload")
	}
	aead, err := getAEAD(key)
	if err != nil {
		return nil, err
	}
	ciphertext := slices.Concat(payload.Ciphertext, payload.AuthTag)
	return aead.Open(nil, payload.Nonce, ciphertext, nil)
}
