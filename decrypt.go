package main

import (
	"fmt"
	"os"
)

// DecryptFile decrypts a file using a key file
func DecryptFile(encryptedFile, keyFile string) (string, error) {
	// Load the encrypted data
	encryptedData, err := LoadEncryptedData(encryptedFile)
	if err != nil {
		return "", fmt.Errorf("error loading encrypted data: %v", err)
	}

	// Load the key data
	_, key, err := LoadKeyData(keyFile)
	if err != nil {
		return "", fmt.Errorf("error loading key data: %v", err)
	}

	// Decrypt the data
	plaintext, err := Decrypt(encryptedData, key)
	if err != nil {
		return "", fmt.Errorf("decryption error: %v", err)
	}

	return plaintext, nil
}

// This function provides a standalone command for decryption
func RunDecrypt() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run decrypt.go [encrypted_file] [key_file]")
		os.Exit(1)
	}

	encryptedFile := os.Args[1]
	keyFile := os.Args[2]

	plaintext, err := DecryptFile(encryptedFile, keyFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Decrypted text:")
	fmt.Println(plaintext)
}

// Uncomment this if you want to compile decrypt.go as a standalone binary
/*
func main() {
	RunDecrypt()
}
*/
