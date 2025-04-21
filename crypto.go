package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Key size for AES-256
	keySize = 32
	// Salt size
	saltSize = 16
	// Number of PBKDF2 iterations
	iterations = 10000
)

// GenerateRandomBytes creates a random byte slice of the specified size
func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateMasterKey creates a new random master key and salt using PBKDF2
func GenerateMasterKey() ([]byte, []byte, error) {
	// Generate a random password
	password, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate password: %v", err)
	}

	// Generate a random salt
	salt, err := GenerateRandomBytes(saltSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive a key using PBKDF2
	masterKey := pbkdf2.Key(password, salt, iterations, keySize, sha256.New)

	return masterKey, salt, nil
}

// Encrypt takes plaintext and a master key, then returns the encrypted data as a base64 string
func Encrypt(plaintext string, masterKey []byte) (string, error) {
	// Generate a random salt for this encryption operation
	salt, err := GenerateRandomBytes(saltSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate encryption salt: %v", err)
	}

	// Create the AES cipher block using the master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create a GCM mode cipher (includes authentication)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate a random nonce
	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Combine the salt with the plaintext
	plaintextWithSalt := append(salt, []byte(plaintext)...)

	// Encrypt the combined data
	// The nonce is prepended to the ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintextWithSalt, nil)

	// Convert to base64 for easier handling
	encodedStr := base64.StdEncoding.EncodeToString(ciphertext)

	return encodedStr, nil
}

// Decrypt takes a base64 encoded string and master key, then returns the decrypted plaintext
func Decrypt(encodedStr string, masterKey []byte) (string, error) {
	// Decode the base64 string
	ciphertext, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// Create the AES cipher block
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create a GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Extract the nonce from the ciphertext
	if len(ciphertext) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Decrypt the ciphertext
	plaintextWithSalt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	// Remove the salt from the plaintext
	if len(plaintextWithSalt) < saltSize {
		return "", fmt.Errorf("decrypted data too short")
	}
	plaintext := plaintextWithSalt[saltSize:]

	return string(plaintext), nil
}
