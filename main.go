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

var salt = []byte{0x28, 0xc8, 0xf2, 0x58, 0xf2, 0xa7, 0x6a, 0xad, 0x7b}

func encrypt(plaintext []byte) ([]byte, error) {
	// Derive key with scrypt
	secretKeyBytes, err := scrypt.Key([]byte("some password"), salt, 1<<15, 8, 1, 32)
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
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, &secretKey)
	return encrypted, nil
}

func decrypt(cipherText []byte) ([]byte, error) {
	secretKeyBytes, err := scrypt.Key([]byte("some password"), salt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)
	var decryptNonce [24]byte
	copy(decryptNonce[:], cipherText[:24])
	decrypted, ok := secretbox.Open(nil, cipherText[24:], &decryptNonce, &secretKey)
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
