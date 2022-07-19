// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

func EncryptNaCl(senderPrivateKey *PrivateKey, recipientPublicKey *PublicKey, input []byte, salt []byte, derivationScheme DerivationScheme) ([]byte, error) {
	var fsalt []byte
	if salt != nil {
		copy(fsalt, salt)
	} else {
		fsalt = make([]byte, 32)
	}
	encryptionKey := deriveSharedKey(senderPrivateKey, recipientPublicKey, fsalt, derivationScheme)

	// Setup IV.
	ivData := MathUtils.GetRandomByteArray(12)

	// Encode.

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipherText := mode.Seal(nil, ivData, input, nil)
	return append(append(cipherText[len(cipherText)-mode.Overhead():], ivData...), cipherText[:len(cipherText)-mode.Overhead()]...), nil
}

func EncryptStringNaCl(senderPrivateKey *PrivateKey, recipientPublicKey *PublicKey, message string, salt []byte, derivationScheme DerivationScheme) ([]byte, error) {

	plainText := []byte(message)
	return EncryptNaCl(senderPrivateKey, recipientPublicKey, plainText, salt, derivationScheme)
}

func DecryptNaCl(recipientPrivateKey *PrivateKey, senderPublicKey *PublicKey, payload []byte, salt []byte, derivationScheme DerivationScheme) ([]byte, error) {
	var fsalt []byte
	if salt != nil {
		copy(fsalt, salt)
	} else {
		fsalt = make([]byte, 32)
	}
	encryptionKey := deriveSharedKey(recipientPrivateKey, senderPublicKey, fsalt, derivationScheme)

	// Decode .

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ivData := payload[16:28]
	encTag := payload[0:16]
	cipherText := append(payload[28:], encTag...)

	decodedText, err := mode.Open(nil, ivData, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return decodedText, nil
}

func deriveSharedSecret(privateKey *PrivateKey, publicKey *PublicKey, derivationScheme DerivationScheme) [32]byte {
	d := PrepareForScalarMultiply(privateKey, derivationScheme)

	// sharedKey = pack(p = d (derived from privateKey) * q (derived from publicKey))
	q := [4][16]int64{gf(nil), gf(nil), gf(nil), gf(nil)}
	p := [4][16]int64{gf(nil), gf(nil), gf(nil), gf(nil)}
	sharedSecret := [32]byte{}
	var keyCopy [32]byte
	var d1 [32]byte
	copy(d1[:], d.Raw)
	copy(keyCopy[:], publicKey.Raw)
	unpack(&q, keyCopy)
	scalarmult(&p, &q, d1)
	pack(&sharedSecret, p)
	return sharedSecret
}
func GetSharedKeyHkdf(privateKey *PrivateKey, publicKey *PublicKey, salt []byte, keyLength int, derivationScheme DerivationScheme) ([]byte, error) {

	grA, err := NewEd25519EncodedGroupElement(publicKey.Raw)
	if err != nil {
		return nil, err
	}
	senderA, err := grA.Decode()
	if err != nil {
		return nil, err
	}
	senderA.PrecomputeForScalarMultiplication()
	el, err := senderA.scalarMultiply(PrepareForScalarMultiply(privateKey, derivationScheme))
	if err != nil {
		return nil, err
	}
	sharedKey, err := el.Encode()
	if err != nil {
		return nil, err
	}
	var hash func() hash.Hash
	switch derivationScheme {
	case Ed25519Sha2:
		hash = sha256.New
	default:
		hash = sha3.New256
	}

	// Non-secret salt, optional (can be nil).
	// Recommended: hash-length random value.

	// Non-secret context info, optional (can be nil).
	info := []byte("catapult")

	// Generate three 128-bit derived keys.
	hkdf := hkdf.New(hash, sharedKey.Raw[:], salt, info)

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}
func deriveSharedKey(privateKey *PrivateKey, publicKey *PublicKey, salt []byte, derivationScheme DerivationScheme) []byte {
	sharedSecret := deriveSharedSecret(privateKey, publicKey, derivationScheme)
	// Underlying hash function for HMAC.
	var hash func() hash.Hash
	switch derivationScheme {
	case Ed25519Sha2:
		hash = sha256.New
	default:
		hash = sha3.New256
	}

	// Non-secret salt, optional (can be nil).
	// Recommended: hash-length random value.

	// Non-secret context info, optional (can be nil).
	info := []byte("catapult")

	// Generate three 128-bit derived keys.
	hkdf := hkdf.New(hash, sharedSecret[:], salt, info)

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}

func encode(message []byte, sharedKey []byte, ivData []byte) ([]byte, error) {
	c, err := aes.NewCipher(sharedKey)

	if err != nil {
		return nil, err
	}

	messageSize := len(message)
	blockSize := c.BlockSize()
	paddingSize := blockSize - (messageSize % blockSize)
	bufferSize := messageSize + paddingSize

	buf := make([]byte, bufferSize)
	copy(buf[:messageSize], message)

	for i := 0; i < paddingSize; i++ {
		buf[messageSize+i] = uint8(paddingSize)
	}

	enc := cipher.NewCBCEncrypter(c, ivData)
	ciphertext := make([]byte, len(buf))
	enc.CryptBlocks(ciphertext, buf)

	return ciphertext, nil
}

func decode(ciphertext []byte, sharedKey []byte, ivData []byte) ([]byte, error) {
	c, err := aes.NewCipher(sharedKey)

	if err != nil {
		return nil, err
	}

	dec := cipher.NewCBCDecrypter(c, ivData)
	buf := make([]byte, len(ciphertext))
	dec.CryptBlocks(buf, ciphertext)

	bufferSize := len(buf)
	paddingSize := int(buf[bufferSize-1] & 0xFF)

	if paddingSize == 0 || paddingSize > c.BlockSize() {
		return nil, errors.New("blocks are corrupted, paddingSize is wrong")
	}

	messageSize := bufferSize - paddingSize

	for i := messageSize; i < bufferSize; i++ {
		if int(buf[i]) != paddingSize {
			return nil, errors.New("blocks are corrupted, fake byte is not equal to paddingSize")
		}
	}

	return buf[:messageSize], nil
}

func encodeGCM(message []byte, sharedKey []byte, ivData []byte) ([]byte, error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipherText := mode.Seal(nil, ivData, plainText, nil)
	return cipherText, nil
}

func decodeGCM(ciphertext []byte, sharedKey []byte, ivData []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err := aesgcm.Open(nil, ivData, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// GetSharedKey create shared bytes
func GetSharedKey(privateKey *PrivateKey, publicKey *PublicKey, salt []byte, keyLength int, derivationScheme DerivationScheme) ([]byte, error) {

	grA, err := NewEd25519EncodedGroupElement(publicKey.Raw)
	if err != nil {
		return nil, err
	}
	senderA, err := grA.Decode()
	if err != nil {
		return nil, err
	}
	senderA.PrecomputeForScalarMultiplication()
	el, err := senderA.scalarMultiply(PrepareForScalarMultiply(privateKey, derivationScheme))
	if err != nil {
		return nil, err
	}
	sharedKey, err := el.Encode()
	if err != nil {
		return nil, err
	}
	for i := 0; i < keyLength; i++ {
		sharedKey.Raw[i] ^= salt[i]
	}
	switch derivationScheme {
	case Ed25519Sha2:
		return HashesSha_256(sharedKey.Raw)
	default:
		return HashesSha3_256(sharedKey.Raw)
	}
}

// Encrypt slice byte
func EncryptGCM(privateKey *PrivateKey, publicKey *PublicKey, keyLength int, input []byte, seed io.Reader, derivationScheme DerivationScheme) ([]byte, error) {
	// Setup salt.
	salt := make([]byte, keyLength)
	_, err := io.ReadFull(seed, salt)
	if err != nil {
		return nil, err
	}

	// Derive shared key.
	sharedKey, err := GetSharedKey(privateKey, publicKey, salt, keyLength, derivationScheme)
	if err != nil {
		return nil, err
	}
	// Setup IV.
	ivData := make([]byte, 12)
	_, err = io.ReadFull(seed, ivData)
	if err != nil {
		return nil, err
	}
	// Encode.
	buf, err := encodeGCM(input, sharedKey, ivData)
	if err != nil {
		return nil, err
	}

	result := append(append(salt, ivData...), buf...)

	return result, nil
}

// Decrypt slice byte
func DecryptGCM(privateKey *PrivateKey, publicKey *PublicKey, keyLength int, input []byte, derivationScheme DerivationScheme) ([]byte, error) {
	if len(input) < 64 {
		return nil, errors.New("input is to short for decryption")
	}

	salt := input[:keyLength]
	ivData := input[keyLength : keyLength+12]
	encData := input[keyLength+12:]
	// Derive shared key.
	sharedKey, err := GetSharedKey(privateKey, publicKey, salt, keyLength, derivationScheme)
	if err != nil {
		return nil, err
	}
	// Decode.
	return decodeGCM(encData, sharedKey, ivData)
}

// Encrypt slice byte
func Encrypt(privateKey *PrivateKey, publicKey *PublicKey, keyLength int, input []byte, seed io.Reader, derivationScheme DerivationScheme) ([]byte, error) {
	// Setup salt.
	salt := make([]byte, keyLength)
	_, err := io.ReadFull(seed, salt)
	if err != nil {
		return nil, err
	}

	// Derive shared key.
	sharedKey, err := GetSharedKey(privateKey, publicKey, salt, keyLength, derivationScheme)
	if err != nil {
		return nil, err
	}
	// Setup IV.
	ivData := make([]byte, 16)
	_, err = io.ReadFull(seed, ivData)
	if err != nil {
		return nil, err
	}
	// Encode.
	buf, err := encode(input, sharedKey, ivData)
	if err != nil {
		return nil, err
	}

	result := append(append(salt, ivData...), buf...)

	return result, nil
}

// Decrypt slice byte
func Decrypt(privateKey *PrivateKey, publicKey *PublicKey, keyLength int, input []byte, derivationScheme DerivationScheme) ([]byte, error) {
	if len(input) < 64 {
		return nil, errors.New("input is to short for decryption")
	}

	salt := input[:keyLength]
	ivData := input[keyLength:48]
	encData := input[48:]
	// Derive shared key.
	sharedKey, err := GetSharedKey(privateKey, publicKey, salt, keyLength, derivationScheme)
	if err != nil {
		return nil, err
	}
	// Decode.
	return decode(encData, sharedKey, ivData)
}

// Verify reports whether sig is a valid signature of message 'data' by publicKey. It
// prevent  panic inside ed25519.Verify
func Verify(keyPair *KeyPair, mess []byte, signature *Signature, scheme DerivationScheme) (res bool) {

	if isEqualConstantTime(keyPair.PublicKey.Raw, make([]byte, 32)) {
		return false
	}

	// h = H(encodedR, encodedA, data).
	rawEncodedR := signature.R
	rawEncodedA := keyPair.PublicKey.Raw
	var hashR []byte
	var err error
	switch scheme {
	case Ed25519Sha2:
		hashR, err = HashesSha_512(
			rawEncodedR,
			rawEncodedA,
			mess)
		break
	case Ed25519Sha3:
		hashR, err = HashesSha3_512(
			rawEncodedR,
			rawEncodedA,
			mess)
		break
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	h, err := NewEd25519EncodedFieldElement(hashR)
	if err != nil {
		fmt.Println(err)
		return false
	}
	// hReduced = h mod group order
	hModQ := h.modQ()
	// Must compute A.
	A, err := (&Ed25519EncodedGroupElement{rawEncodedA}).Decode()
	if err != nil {
		fmt.Println(err)
		return false
	}
	A.PrecomputeForDoubleScalarMultiplication()
	// R = encodedS * B - H(encodedR, encodedA, data) * A
	calculatedR, err := Ed25519Group.BASE_POINT().doubleScalarMultiplyVariableTime(
		A,
		hModQ,
		&Ed25519EncodedFieldElement{Ed25519FieldZeroShort(), signature.S})
	if err != nil {
		fmt.Println(err)
		return false
	}
	// Compare calculated R to given R.
	encodedCalculatedR, err := calculatedR.Encode()
	if err != nil {
		fmt.Println(err)
		return false
	}

	return isEqualConstantTime(encodedCalculatedR.Raw, rawEncodedR)
}

func Sign(keyPair *KeyPair, mess []byte, derivationScheme DerivationScheme) (*Signature, error) {
	if !keyPair.HasPrivateKey() {
		return nil, errors.New("cannot sign without private key")
	}

	// Hash the private key to improve randomness.
	var err error
	var hash []byte
	var hashR []byte
	var hashH []byte
	// r = H(hash_b,...,hash_2b-1, data) where b=256.
	switch derivationScheme {
	case Ed25519Sha2:
		hash, err = HashesSha_512(keyPair.PrivateKey.Raw)
		if err != nil {
			return nil, err
		}
		hashR, err = HashesSha_512(
			hash[32:], // only include the last 32 bytes of the private key hash
			mess)
	case Ed25519Sha3:
		hash, err = HashesSha3_512(keyPair.PrivateKey.Raw)
		if err != nil {
			return nil, err
		}
		hashR, err = HashesSha3_512(
			hash[32:], // only include the last 32 bytes of the private key hash
			mess)
	}
	if err != nil {
		return nil, err
	}
	r, err := NewEd25519EncodedFieldElement(hashR)
	if err != nil {
		return nil, err
	}
	// Reduce size of r since we are calculating mod group order anyway
	rModQ := r.modQ()
	// R = rModQ * base point.
	R, err := Ed25519Group.BASE_POINT().scalarMultiply(rModQ)
	if err != nil {
		return nil, err
	}
	encodedR, err := R.Encode()
	if err != nil {
		return nil, err
	}
	// S = (r + H(encodedR, encodedA, data) * a) mod group order where
	// encodedR and encodedA are the little endian encodings of the group element R and the public key A and
	// a is the lower 32 bytes of hash after clamping.
	switch derivationScheme {
	case Ed25519Sha2:
		hashH, err = HashesSha_512(encodedR.Raw,
			keyPair.PublicKey.Raw,
			mess)
	case Ed25519Sha3:
		hashH, err = HashesSha3_512(encodedR.Raw,
			keyPair.PublicKey.Raw,
			mess)
	}
	if err != nil {
		return nil, err
	}
	h, err := NewEd25519EncodedFieldElement(hashH)
	if err != nil {
		return nil, err
	}
	hModQ := h.modQ()
	encodedS := hModQ.multiplyAndAddModQ(PrepareForScalarMultiply(keyPair.PrivateKey, derivationScheme),
		rModQ)
	// Signature is (encodedR, encodedS)
	signature, err := NewSignature(encodedR.Raw, encodedS.Raw)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Ed2551Sha3SeedCryptoEngine wraps a cryptographic engine ed25519 with sha3 hashing and seed for this engine
type Ed25519Sha3SeedCryptoEngine struct {
	seed io.Reader
}

// CreateDsaSigner implemented interface CryptoEngine method
func (ref *Ed25519Sha3SeedCryptoEngine) CreateDsaSigner(keyPair *KeyPair) DsaSigner {
	return NewEd25519Sha3DsaSigner(keyPair)
}

// derivation scheme interface CryptoEngine method
func (ref *Ed25519Sha3SeedCryptoEngine) EngineDerivationScheme() DerivationScheme {
	return Ed25519Sha3
}

// CreateKeyGenerator implemented interface CryptoEngine method
func (ref *Ed25519Sha3SeedCryptoEngine) CreateKeyGenerator() KeyGenerator {
	return NewEd25519Sha3KeyGenerator(ref.seed)
}

// CreateBlockCipher implemented interface CryptoEngine method
func (ref *Ed25519Sha3SeedCryptoEngine) CreateBlockCipher(senderKeyPair *KeyPair, recipientKeyPair *KeyPair) BlockCipher {
	return NewEd25519Sha3BlockCipher(senderKeyPair, recipientKeyPair, ref.seed)
}

// CreateKeyAnalyzer implemented interface CryptoEngine method
func (ref *Ed25519Sha3SeedCryptoEngine) CreateKeyAnalyzer() KeyAnalyzer {
	return NewEd25519KeyAnalyzer()
}

// Ed2551Sha2SeedCryptoEngine wraps a cryptographic engine ed25519 with Sha2 hashing and seed for this engine
type Ed25519Sha2SeedCryptoEngine struct {
	seed io.Reader
}

// derivation scheme interface CryptoEngine method
func (ref *Ed25519Sha2SeedCryptoEngine) EngineDerivationScheme() DerivationScheme {
	return Ed25519Sha2
}

// CreateDsaSigner implemented interface CryptoEngine method
func (ref *Ed25519Sha2SeedCryptoEngine) CreateDsaSigner(keyPair *KeyPair) DsaSigner {
	return NewEd25519Sha2DsaSigner(keyPair)
}

// CreateKeyGenerator implemented interface CryptoEngine method
func (ref *Ed25519Sha2SeedCryptoEngine) CreateKeyGenerator() KeyGenerator {
	return NewEd25519Sha2KeyGenerator(ref.seed)
}

// CreateBlockCipher implemented interface CryptoEngine method
func (ref *Ed25519Sha2SeedCryptoEngine) CreateBlockCipher(senderKeyPair *KeyPair, recipientKeyPair *KeyPair) BlockCipher {
	return NewEd25519Sha2BlockCipher(senderKeyPair, recipientKeyPair, ref.seed)
}

// CreateKeyAnalyzer implemented interface CryptoEngine method
func (ref *Ed25519Sha2SeedCryptoEngine) CreateKeyAnalyzer() KeyAnalyzer {
	return NewEd25519KeyAnalyzer()
}

// Ed25519BlockCipher Implementation of the block cipher for Ed25519.
type Ed25519Sha3BlockCipher struct {
	senderKeyPair    *KeyPair
	recipientKeyPair *KeyPair
	keyLength        int
	seed             io.Reader
}

// NewEd25519BlockCipher return Ed25519BlockCipher
func NewEd25519Sha3BlockCipher(senderKeyPair *KeyPair, recipientKeyPair *KeyPair, seed io.Reader) *Ed25519Sha3BlockCipher {
	if seed == nil {
		seed = rand.Reader
	}

	ref := Ed25519Sha3BlockCipher{
		senderKeyPair,
		recipientKeyPair,
		len(recipientKeyPair.PublicKey.Raw),
		seed,
	}
	return &ref
}

// Encrypt slice byte
func (ref *Ed25519Sha3BlockCipher) EncryptGCM(input []byte) ([]byte, error) {
	return EncryptGCM(ref.senderKeyPair.PrivateKey, ref.recipientKeyPair.PublicKey, ref.keyLength, input, ref.seed, Ed25519Sha3)
}

// Decrypt slice byte
func (ref *Ed25519Sha3BlockCipher) DecryptGCM(input []byte) ([]byte, error) {
	// Decode.
	return DecryptGCM(ref.recipientKeyPair.PrivateKey, ref.senderKeyPair.PublicKey, ref.keyLength, input, Ed25519Sha3)
}

// Encrypt slice byte
func (ref *Ed25519Sha3BlockCipher) Encrypt(input []byte) ([]byte, error) {
	// Setup salt.
	return Encrypt(ref.senderKeyPair.PrivateKey, ref.recipientKeyPair.PublicKey, ref.keyLength, input, ref.seed, Ed25519Sha3)
}

// Decrypt slice byte
func (ref *Ed25519Sha3BlockCipher) Decrypt(input []byte) ([]byte, error) {
	return Decrypt(ref.recipientKeyPair.PrivateKey, ref.senderKeyPair.PublicKey, ref.keyLength, input, Ed25519Sha3)
}

// Encrypt slice byte with NaCl
func (ref *Ed25519Sha3BlockCipher) EncryptGCMNacl(input []byte, salt []byte) ([]byte, error) {
	return EncryptNaCl(ref.senderKeyPair.PrivateKey, ref.recipientKeyPair.PublicKey, input, salt, Ed25519Sha3)
}

// Decrypt slice byte with NaCl
func (ref *Ed25519Sha3BlockCipher) DecryptGCMNacl(input []byte, salt []byte) ([]byte, error) {
	// Decode.
	return DecryptNaCl(ref.recipientKeyPair.PrivateKey, ref.senderKeyPair.PublicKey, input, salt, Ed25519Sha3)
}

// Ed25519BlockCipher Implementation of the block cipher for Ed25519.
type Ed25519Sha2BlockCipher struct {
	senderKeyPair    *KeyPair
	recipientKeyPair *KeyPair
	keyLength        int
	seed             io.Reader
}

// NewEd25519BlockCipher return Ed25519BlockCipher
func NewEd25519Sha2BlockCipher(senderKeyPair *KeyPair, recipientKeyPair *KeyPair, seed io.Reader) *Ed25519Sha2BlockCipher {
	if seed == nil {
		seed = rand.Reader
	}

	ref := Ed25519Sha2BlockCipher{
		senderKeyPair,
		recipientKeyPair,
		len(recipientKeyPair.PublicKey.Raw),
		seed,
	}
	return &ref
}

// Encrypt slice byte
func (ref *Ed25519Sha2BlockCipher) EncryptGCM(input []byte) ([]byte, error) {
	return EncryptGCM(ref.senderKeyPair.PrivateKey, ref.recipientKeyPair.PublicKey, ref.keyLength, input, ref.seed, Ed25519Sha2)
}

// Decrypt slice byte
func (ref *Ed25519Sha2BlockCipher) DecryptGCM(input []byte) ([]byte, error) {
	// Decode.
	return DecryptGCM(ref.recipientKeyPair.PrivateKey, ref.senderKeyPair.PublicKey, ref.keyLength, input, Ed25519Sha2)
}

// Encrypt slice byte with NaCl
func (ref *Ed25519Sha2BlockCipher) EncryptGCMNacl(input []byte, salt []byte) ([]byte, error) {
	return EncryptNaCl(ref.senderKeyPair.PrivateKey, ref.recipientKeyPair.PublicKey, input, salt, Ed25519Sha2)
}

// Decrypt slice byte with NaCl
func (ref *Ed25519Sha2BlockCipher) DecryptGCMNacl(input []byte, salt []byte) ([]byte, error) {
	// Decode.
	return DecryptNaCl(ref.recipientKeyPair.PrivateKey, ref.senderKeyPair.PublicKey, input, salt, Ed25519Sha2)
}

// Encrypt slice byte
func (ref *Ed25519Sha2BlockCipher) Encrypt(input []byte) ([]byte, error) {
	// Setup salt.
	return Encrypt(ref.senderKeyPair.PrivateKey, ref.recipientKeyPair.PublicKey, ref.keyLength, input, ref.seed, Ed25519Sha2)
}

// Decrypt slice byte
func (ref *Ed25519Sha2BlockCipher) Decrypt(input []byte) ([]byte, error) {
	return Decrypt(ref.recipientKeyPair.PrivateKey, ref.senderKeyPair.PublicKey, ref.keyLength, input, Ed25519Sha2)
}

// Ed25519DsaSigner implement DsaSigned interface with Ed25519 algo
type Ed25519Sha3DsaSigner struct {
	KeyPair *KeyPair
}

// NewEd25519DsaSigner creates a Ed25519 DSA signer.
func NewEd25519Sha3DsaSigner(keyPair *KeyPair) *Ed25519Sha3DsaSigner {
	return &Ed25519Sha3DsaSigner{keyPair}
}

// Sign message
func (ref *Ed25519Sha3DsaSigner) Sign(mess []byte) (*Signature, error) {

	signature, err := Sign(ref.KeyPair, mess, Ed25519Sha3)
	if err != nil {
		return nil, err
	}
	if !ref.IsCanonicalSignature(signature) {
		return nil, errors.New("Generated signature is not canonical")
	}

	return signature, nil
}

// Verify reports whether sig is a valid signature of message 'data' by publicKey. It
// prevent  panic inside ed25519.Verify
func (ref *Ed25519Sha3DsaSigner) Verify(mess []byte, signature *Signature) (res bool) {

	if !ref.IsCanonicalSignature(signature) {
		return false
	}
	return Verify(ref.KeyPair, mess, signature, Ed25519Sha3)
}

// IsCanonicalSignature check signature on canonical
func (ref *Ed25519Sha3DsaSigner) IsCanonicalSignature(signature *Signature) bool {

	sgnS := signature.GetS().Uint64()
	return sgnS != Ed25519Group.GROUP_ORDER.Uint64() && sgnS > 0
}

// MakeSignatureCanonical return canonical signature
func (ref *Ed25519Sha3DsaSigner) MakeSignatureCanonical(signature *Signature) (*Signature, error) {

	sign := make([]byte, 64)
	copy(sign, signature.S)
	s, err := NewEd25519EncodedFieldElement(sign)
	if err != nil {
		return nil, err
	}
	sModQ := s.modQ()
	return NewSignature(signature.R, sModQ.Raw)
}

// Ed25519DsaSigner implement DsaSigned interface with Ed25519 algo
type Ed25519Sha2DsaSigner struct {
	KeyPair *KeyPair
}

// NewEd25519DsaSigner creates a Ed25519 DSA signer.
func NewEd25519Sha2DsaSigner(keyPair *KeyPair) *Ed25519Sha2DsaSigner {
	return &Ed25519Sha2DsaSigner{keyPair}
}

// Sign message
func (ref *Ed25519Sha2DsaSigner) Sign(mess []byte) (*Signature, error) {

	signature, err := Sign(ref.KeyPair, mess, Ed25519Sha2)
	if err != nil {
		return nil, err
	}
	if !ref.IsCanonicalSignature(signature) {
		return nil, errors.New("Generated signature is not canonical")
	}

	return signature, nil
}

// Verify reports whether sig is a valid signature of message 'data' by publicKey. It
// prevent  panic inside ed25519.Verify
func (ref *Ed25519Sha2DsaSigner) Verify(mess []byte, signature *Signature) (res bool) {

	if !ref.IsCanonicalSignature(signature) {
		return false
	}

	return Verify(ref.KeyPair, mess, signature, Ed25519Sha2)
}

// IsCanonicalSignature check signature on canonical
func (ref *Ed25519Sha2DsaSigner) IsCanonicalSignature(signature *Signature) bool {

	sgnS := signature.GetS().Uint64()
	return sgnS != Ed25519Group.GROUP_ORDER.Uint64() && sgnS > 0
}

// MakeSignatureCanonical return canonical signature
func (ref *Ed25519Sha2DsaSigner) MakeSignatureCanonical(signature *Signature) (*Signature, error) {

	sign := make([]byte, 64)
	copy(sign, signature.S)
	s, err := NewEd25519EncodedFieldElement(sign)
	if err != nil {
		return nil, err
	}
	sModQ := s.modQ()
	return NewSignature(signature.R, sModQ.Raw)
}

// Ed25519KeyGenerator Implementation of the key generator for Ed25519 using Sha2 hashing.
type Ed25519Sha2KeyGenerator struct {
	seed io.Reader
}

// NewEd25519KeyGenerator return new Ed25519KeyGenerator
func NewEd25519Sha2KeyGenerator(seed io.Reader) *Ed25519Sha2KeyGenerator {
	if seed == nil {
		seed = rand.Reader
	}

	ref := Ed25519Sha2KeyGenerator{seed}
	return &ref
}

// GenerateKeyPair generate key pair use ed25519.GenerateKey
func (ref *Ed25519Sha2KeyGenerator) GenerateKeyPair() (*KeyPair, error) {
	seed := make([]byte, 32)
	_, err := io.ReadFull(ref.seed, seed[:])
	if err != nil {
		return nil, err
	} // seed is the private key.

	// seed is the private key.
	privateKey := NewPrivateKey(seed)
	publicKey := ref.DerivePublicKey(privateKey)
	return NewKeyPair(privateKey, publicKey, CryptoEngines.Ed25519Sha2Engine)
}

// DerivePublicKey return public key based on Ed25519Group.BASE_POINT
func (ref *Ed25519Sha2KeyGenerator) DerivePublicKey(privateKey *PrivateKey) *PublicKey {

	a := PrepareForScalarMultiply(privateKey, Ed25519Sha2)
	// a * base point is the public key.
	pubKey, err := Ed25519Group.BASE_POINT().scalarMultiply(a)
	if err != nil {
		panic(err)
	}
	el, _ := pubKey.Encode()
	return NewPublicKey(el.Raw)
}

// Ed25519KeyGenerator Implementation of the key generator for Ed25519 using Sha3 hashing.
type Ed25519Sha3KeyGenerator struct {
	seed io.Reader
}

// Ed25519Sha3KeyGenerator return new Ed25519Sha3KeyGenerator
func NewEd25519Sha3KeyGenerator(seed io.Reader) *Ed25519Sha3KeyGenerator {
	if seed == nil {
		seed = rand.Reader
	}

	ref := Ed25519Sha3KeyGenerator{seed}
	return &ref
}

// GenerateKeyPair generate key pair use ed25519.GenerateKey
func (ref *Ed25519Sha3KeyGenerator) GenerateKeyPair() (*KeyPair, error) {
	seed := make([]byte, 32)
	_, err := io.ReadFull(ref.seed, seed[:])
	if err != nil {
		return nil, err
	} // seed is the private key.

	// seed is the private key.
	privateKey := NewPrivateKey(seed)
	publicKey := ref.DerivePublicKey(privateKey)
	return NewKeyPair(privateKey, publicKey, CryptoEngines.Ed25519Sha3Engine)
}

// DerivePublicKey return public key based on Ed25519Group.BASE_POINT
func (ref *Ed25519Sha3KeyGenerator) DerivePublicKey(privateKey *PrivateKey) *PublicKey {

	a := PrepareForScalarMultiply(privateKey, Ed25519Sha3)
	// a * base point is the public key.
	pubKey, err := Ed25519Group.BASE_POINT().scalarMultiply(a)
	if err != nil {
		panic(err)
	}
	el, _ := pubKey.Encode()
	return NewPublicKey(el.Raw)
}
