package derpcipher

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
)

type EncryptedObject struct {
	kdfSalt    []byte
	encrNonce  [24]byte
	cipherText []byte
}

func (e *EncryptedObject) CipherText() []byte {
	return e.cipherText
}

func NewEncryptedObject() *EncryptedObject {
	// Generate random salt for KDF
	var salt = make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		panic(err)
	}
	// Random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	return &EncryptedObject{kdfSalt: salt, encrNonce: nonce}
}

// encrypts byte slice with a pass
func (e *EncryptedObject) Encrypt(plainText []byte, pass string) error {

	// Derive key with scrypt
	secretKeyBytes, err := scrypt.Key([]byte(pass), e.kdfSalt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	// Random nonce
	encrypted := secretbox.Seal(e.encrNonce[:], plainText, &e.encrNonce, &secretKey)
	// Add the salt at the beginning of the message:
	encrypted = append(e.kdfSalt, encrypted...)
	e.cipherText = encrypted
	return nil
}

// This function puts the KDF salt, encryption nonce and ciphertext all together
func (e *EncryptedObject) PackMessage() error {
}

// Constructor that reads a file, parse
func NewEncryptedObjectFromFile() {
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

// writes bytes to file
func ToFile(info []byte, filename string) error {
	if filename == "" {
		panic("Cannot write to an empty path")
	}
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	encoded := base64.StdEncoding.EncodeToString(info)
	f.WriteString(encoded)
	return nil

}
