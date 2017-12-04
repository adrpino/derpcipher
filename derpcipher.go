package derpcipher

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
)

type cipherText struct {
	salt    []byte
	nonce   [24]byte
	content []byte
}

// encrypts byte slice with a pass
func Encrypt(plainText []byte, pass string) ([]byte, error) {
	// Generate random salt for KDF
	var salt = make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		panic(err)
	}
	// Derive key with scrypt
	secretKeyBytes, err := scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	// encode it to hex
	encodedKey := hex.EncodeToString(secretKeyBytes)
	_ = encodedKey
	// Random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	encrypted := secretbox.Seal(nonce[:], plainText, &nonce, &secretKey)
	// Add the salt at the beginning of the message:
	encrypted = append(salt, encrypted...)
	return encrypted, nil
}

// Decrypts a slice of bytes
func Decrypt(cipherText []byte, pass string) ([]byte, error) {
	// First 8 bytes of cyphertext is salt
	var msgSalt = make([]byte, 8)
	copy(msgSalt[:], cipherText[:8])
	secretKeyBytes, err := scrypt.Key([]byte(pass), msgSalt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	var decryptNonce [24]byte
	// First 24 following is nonce
	copy(decryptNonce[:], cipherText[8:(8+24)])
	decrypted, ok := secretbox.Open(nil, cipherText[(8+24):], &decryptNonce, &secretKey)
	if !ok {
		panic("decryption error")
	}
	return decrypted, nil
}

// writes ciphertext to file
func toFile(cipherText []byte, filename string, asText bool) error {
	if filename == "" {
		panic("Cannot write to an empty path")
	}
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var encoded string
	if asText {
		encoded = hex.EncodeToString(cipherText)
		f.WriteString(encoded)
	}
	return nil

}
