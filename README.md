# Crypter

A secure file encryption tool using AES-256 encryption with PBKDF2 key derivation.

## Features

- AES-256 encryption with GCM mode for authenticated encryption
- PBKDF2 key derivation with random salt for secure key generation
- Unique output for every encryption, even with identical inputs
- File-based storage for encrypted data and keys

## Project Structure

- `main.go` - Main program entry point
- `crypto.go` - Core encryption and decryption functions
- `fileutils.go` - File handling utilities
- `decrypt.go` - Standalone decryption functionality

## Setup

1. Ensure you have Go installed (1.18 or newer)
2. Install dependencies:
   ```
   go mod tidy
   ```

## Usage

### Encryption

Run the main program:

```
go run *.go
```

You will be prompted for:
1. Text to encrypt
2. A filename for the output (without extension)

Two files will be created:
- `[filename].enc` - The encrypted data
- `[filename].key` - The decryption key file containing salt and key

### Decryption

To decrypt a file, you can use the provided functions in your code:

```go
plaintext, err := DecryptFile("secret.enc", "secret.key")
if err != nil {
    fmt.Printf("Error: %v\n", err)
    return
}
fmt.Printf("Decrypted: %s\n", plaintext)
```

## Security Notes

- Keep the `.key` file secure and separate from the `.enc` file
- The security of this encryption relies on protecting the key file
- For production use, consider implementing more secure key management

## How It Works

1. A master key is generated using PBKDF2 with a random salt
2. For each encryption operation:
   - A new random salt is generated
   - The salt is combined with the plaintext
   - The combined data is encrypted with AES-GCM
   - The result is encoded as base64

This ensures that even if the same text is encrypted multiple times, the output will be different each time due to the random salt.