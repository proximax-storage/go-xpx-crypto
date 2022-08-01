// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// HashesSha_256 return Sha 256 hash of byte
func HashesSha_256(b []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// HashesKeccak_256 return Keccak 256 hash of byte
func HashesKeccak_256(b []byte) ([]byte, error) {
	hash := sha3.NewLegacyKeccak256()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// HashesSha3_256 return sha3 256 hash of byte
func HashesSha3_256(b []byte) ([]byte, error) {
	hash := sha3.New256()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// HashesSha_512 return sha 512 hash of byte
func HashesSha_512(inputs ...[]byte) ([]byte, error) {
	hash := sha512.New()
	for _, b := range inputs {

		_, err := hash.Write(b)
		if err != nil {
			return nil, err
		}
	}

	return hash.Sum(nil), nil
}

// HashesSha3_512 return sha3 512 hash of byte
func HashesSha3_512(inputs ...[]byte) ([]byte, error) {
	hash := sha3.New512()
	for _, b := range inputs {

		_, err := hash.Write(b)
		if err != nil {
			return nil, err
		}
	}

	return hash.Sum(nil), nil
}

// HashesRipemd160  return ripemd160 hash of byte
func HashesRipemd160(b []byte) ([]byte, error) {
	hash := ripemd160.New()
	_, err := hash.Write(b)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil

}

func isNegativeConstantTime(b int) int {
	return (b >> 8) & 1
}

func isConstantTimeByteEq(b, c int) int {

	result := 0
	xor := b ^ c // final
	for i := uint(0); i < 8; i++ {
		result |= xor >> i
	}

	return (result ^ 0x01) & 0x01
}

func isEqualConstantTime(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

func EncodeMessageEd25519(senderPrivateKey *PrivateKey, recipientPublicKey *PublicKey, message string) (string, error) {

	sender, _ := NewKeyPair(senderPrivateKey, nil, nil)
	recipient, _ := NewKeyPair(nil, recipientPublicKey, nil)
	cipher := NewEd25519Sha2BlockCipher(sender, recipient, nil)
	payload := []byte(message)
	plainText, err := cipher.EncryptGCM(payload)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(plainText), nil
}

func DecodeMessageEd25519(recipientPrivateKey *PrivateKey, senderPublicKey *PublicKey, payload []byte) (string, error) {

	recipient, _ := NewKeyPair(recipientPrivateKey, nil, nil)
	sender, _ := NewKeyPair(nil, senderPublicKey, nil)
	cipher := NewEd25519Sha2BlockCipher(sender, recipient, nil)
	plainText, err := cipher.DecryptGCM(payload)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}
