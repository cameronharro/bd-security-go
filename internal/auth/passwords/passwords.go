package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength = 128

	A2IDMemory      uint32 = 19 * 1024
	A2IDIterations  uint32 = 2
	A2IDParallelism uint8  = 1
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, A2IDIterations, A2IDMemory, A2IDParallelism, 32)
	return encodeArgon2idHash(
		argon2idHash{
			version:     argon2.Version,
			memoryKiB:   A2IDMemory,
			iterations:  A2IDIterations,
			parallelism: A2IDParallelism,
			salt:        salt,
			derivedKey:  key,
		},
	), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}

	parsedArgon2id, valid := parseArgon2idHash(encodedHash)
	if !valid || parsedArgon2id.version != argon2.Version {
		return false
	}
	derivedKey := argon2.IDKey(
		[]byte(password),
		parsedArgon2id.salt,
		parsedArgon2id.iterations,
		parsedArgon2id.memoryKiB,
		parsedArgon2id.parallelism,
		32,
	)
	return subtle.ConstantTimeCompare(derivedKey, parsedArgon2id.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, isLegacyHash := decodeLegacyHash(encodedHash); isLegacyHash {
		return true
	}
	if parsedA2IDHash, ok := parseArgon2idHash(encodedHash); ok {
		if parsedA2IDHash.memoryKiB != A2IDMemory {
			return true
		}
		if parsedA2IDHash.iterations != A2IDIterations {
			return true
		}
		if parsedA2IDHash.parallelism != A2IDParallelism {
			return true
		}
	}
	return false
}
