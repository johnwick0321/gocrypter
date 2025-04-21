package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
)

// SaveEncryptedData saves encrypted data to a file
func SaveEncryptedData(data string, filename string) error {
	return ioutil.WriteFile(filename, []byte(data), 0644)
}

// SaveKeyData saves the salt and key to a file
func SaveKeyData(salt []byte, key []byte, filename string) error {
	keyData := fmt.Sprintf("Salt: %s\nKey: %s",
		base64.StdEncoding.EncodeToString(salt),
		hex.EncodeToString(key))
	return ioutil.WriteFile(filename, []byte(keyData), 0600) // More restrictive permissions for the key
}

// LoadKeyData loads the salt and key from a key file
func LoadKeyData(filename string) ([]byte, []byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, nil, fmt.Errorf("invalid key file format")
	}

	saltLine := strings.TrimPrefix(lines[0], "Salt: ")
	keyLine := strings.TrimPrefix(lines[1], "Key: ")

	salt, err := base64.StdEncoding.DecodeString(saltLine)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %v", err)
	}

	key, err := hex.DecodeString(keyLine)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode key: %v", err)
	}

	return salt, key, nil
}

// LoadEncryptedData loads encrypted data from a file
func LoadEncryptedData(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read encrypted file: %v", err)
	}

	return string(data), nil
}
