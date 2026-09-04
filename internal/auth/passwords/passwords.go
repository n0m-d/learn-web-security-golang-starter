package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength           = 128
	argon2idSaltLength  = 16
	argon2idKeyLength   = 32
	argon2idMemoryKiB   = 19 * 1024
	argon2idIterations  = 2
	argon2idParallelism = 1
)

func Hash(password string) (string, error) {
	if len(password) > MaxLength {
		return "", errors.New("password exceeds maximum length")
	}
	salt := make([]byte, argon2idSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	derivedKey := argon2.IDKey([]byte(password), salt, argon2idIterations, argon2idMemoryKiB, argon2idParallelism, argon2idKeyLength)
	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   argon2idMemoryKiB,
		iterations:  argon2idIterations,
		parallelism: argon2idParallelism,
		salt:        salt,
		derivedKey:  derivedKey,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if len(password) > MaxLength {
		return false
	}
	if legacyHash, ok := decodeLegacyHash(encodedHash); ok {
		digest := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(digest[:], legacyHash) == 1
	}
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedHash.version != argon2.Version {
		return false
	}
	candidate := argon2.IDKey(
		[]byte(password),
		parsedHash.salt,
		parsedHash.iterations,
		parsedHash.memoryKiB,
		parsedHash.parallelism,
		uint32(len(parsedHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidate, parsedHash.derivedKey) == 1
}

func NeedsRehash(string) bool {
	return false
}
