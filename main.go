package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
)

// encrypts byte slice with a pass
func encrypt(plaintext []byte) ([]byte, error) {
	// Generate random salt for KDF
	var salt = make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		panic(err)
	}
	// Derive key with scrypt
	secretKeyBytes, err := scrypt.Key([]byte("some password"), salt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(secretKeyBytes))
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
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, &secretKey)
	// Add the salt at the beginning of the message:
	encrypted = append(salt, encrypted...)
	return encrypted, nil
}

// Decrypts a slice of bytes
func decrypt(cipherText []byte) ([]byte, error) {
	// First 8 bytes of cyphertext is salt
	var msgSalt = make([]byte, 8)
	copy(msgSalt[:], cipherText[:8])
	secretKeyBytes, err := scrypt.Key([]byte("some password"), msgSalt, 1<<15, 8, 1, 32)
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

func main() {
	fmt.Print("Enter text: ")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	encrypted, err := encrypt([]byte(text))
	fmt.Println("encrypted", string(encrypted))

	decrypted, err := decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypted))
}
