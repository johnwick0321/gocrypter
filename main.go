package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	// Get user input
	fmt.Print("Enter text to encrypt: ")
	var input string
	fmt.Scanln(&input)

	// Get a filename for the encrypted output
	fmt.Print("Enter filename for encrypted output (without extension): ")
	var filename string
	fmt.Scanln(&filename)

	encryptedFilename := filename + ".enc"
	keyFilename := filename + ".key"

	// Generate a master key and salt using PBKDF2
	masterKey, salt, err := GenerateMasterKey()
	if err != nil {
		fmt.Printf("Error generating master key: %v\n", err)
		os.Exit(1)
	}

	// Encrypt the input
	encrypted, err := Encrypt(input, masterKey)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		os.Exit(1)
	}

	// Save the encrypted data to a file
	err = ioutil.WriteFile(encryptedFilename, []byte(encrypted), 0644)
	if err != nil {
		fmt.Printf("Error writing encrypted file: %v\n", err)
		os.Exit(1)
	}

	// Save the decryption key (salt + master key) to a file
	keyData := fmt.Sprintf("Salt: %s\nKey: %s",
		base64.StdEncoding.EncodeToString(salt),
		hex.EncodeToString(masterKey))
	err = ioutil.WriteFile(keyFilename, []byte(keyData), 0600) // More restrictive permissions for the key
	if err != nil {
		fmt.Printf("Error writing key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted data saved to: %s\n", encryptedFilename)
	fmt.Printf("Decryption key saved to: %s\n", keyFilename)

	// Optionally demonstrate decryption
	fmt.Println("\nDemonstrating decryption:")
	decrypted, err := Decrypt(encrypted, masterKey)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Decrypted text: %s\n", decrypted)
}
