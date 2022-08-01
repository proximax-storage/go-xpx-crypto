package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	message             = "NEM is awesome !"
	senderPrivateKey    = "2a91e1d5c110a8d0105aad4683f962c2a56663a3cad46666b16d243174673d90"
	recipientPrivateKey = "2618090794e9c9682f2ac6504369a2f4fb9fe7ee7746f9560aca228d355b1cb9"
	iv                  = "e1409b724bf6b591456a19ad4caa6932"
	salt                = "4ff36df9cbc91e740867c70b8787cf83b073949bbfb0e8e6d451fe32774dfe1f"
	encrypted           = "4ff36df9cbc91e740867c70b8787cf83b073949bbfb0e8e6d451fe32774dfe1fe1409b724bf6b591456a19ad4caa6932fcbf5c4898480f73082181d93f4f089b0e92de37c612e2c80c981874eb1be197"
)

type FakeReader struct {
	buf    []byte
	offset int
}

func (ref *FakeReader) Read(p []byte) (n int, err error) {
	if len(ref.buf)-ref.offset < len(p) {
		return 0, errors.New("not enough bytes in fake buffer")
	}

	for i, _ := range p {
		p[i] = ref.buf[ref.offset]
		ref.offset++
	}

	return len(p), nil
}

func NewFakeReader(bufs ...string) (*FakeReader, error) {
	b := make([]byte, 0)
	for _, buf := range bufs {
		eB, err := hex.DecodeString(buf)

		if err != nil {
			return nil, err
		}

		b = append(b, eB...)
	}

	reader := FakeReader{b, 0}
	return &reader, nil
}

func Test_Encrypt(t *testing.T) {
	sender, err := NewPrivateKeyfromHexString(senderPrivateKey)
	assert.Nil(t, err)
	senderkp, err := NewKeyPair(sender, nil, nil)
	assert.Nil(t, err)
	recipient, err := NewPrivateKeyfromHexString(recipientPrivateKey)
	assert.Nil(t, err)
	recipientkp, err := NewKeyPair(recipient, nil, nil)
	assert.Nil(t, err)

	reader, err := NewFakeReader(salt, iv)
	assert.Nil(t, err)
	engine := Ed25519Sha3SeedCryptoEngine{reader}
	blockCipher := engine.CreateBlockCipher(senderkp, recipientkp)
	encodedMessage, err := blockCipher.Encrypt([]byte(message))
	assert.Nil(t, err)
	assert.Equal(t, encrypted, hex.EncodeToString(encodedMessage))
}

func Test_Decrypt(t *testing.T) {
	sender, err := NewPrivateKeyfromHexString(senderPrivateKey)
	assert.Nil(t, err)
	senderkp, err := NewKeyPair(sender, nil, nil)
	assert.Nil(t, err)
	recipient, err := NewPrivateKeyfromHexString(recipientPrivateKey)
	assert.Nil(t, err)
	recipientkp, err := NewKeyPair(recipient, nil, nil)
	assert.Nil(t, err)

	blockCipher := NewBlockCipher(senderkp, recipientkp, nil)
	eB, err := hex.DecodeString(encrypted)
	assert.Nil(t, err)
	str, err := blockCipher.Decrypt(eB)
	assert.Nil(t, err)
	assert.Equal(t, message, string(str))
}

func Test_EncryptAndDecrypt(t *testing.T) {
	sender, err := NewPrivateKeyfromHexString(senderPrivateKey)
	assert.Nil(t, err)
	senderkp, err := NewKeyPair(sender, nil, nil)
	assert.Nil(t, err)
	recipient, err := NewPrivateKeyfromHexString(recipientPrivateKey)
	assert.Nil(t, err)
	recipientkp, err := NewKeyPair(recipient, nil, nil)
	assert.Nil(t, err)

	blockCipherEncrypt := NewBlockCipher(senderkp, recipientkp, nil)
	blockCipherDecrypt := NewBlockCipher(senderkp, recipientkp, nil)
	encryptedData, err := blockCipherEncrypt.Encrypt([]byte(message))
	assert.Nil(t, err)
	decryptedData, err := blockCipherDecrypt.Decrypt(encryptedData)
	assert.Nil(t, err)
	assert.Equal(t, message, string(decryptedData))
}

func TestEncryptDecryptGCMDefault(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	startMessage := "This is a random test message that must match forever and ever."
	encoded, err := EncodeMessageEd25519(sender.PrivateKey, recipient.PublicKey, startMessage)
	assert.Nil(t, err)
	decodedStr, err := hex.DecodeString(encoded)
	assert.Nil(t, err)
	decoded, err := DecodeMessageEd25519(recipient.PrivateKey, sender.PublicKey, decodedStr)
	assert.Nil(t, err)
	assert.Equal(t, startMessage, decoded)
}

func TestEncryptDecryptGCMNaCl(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	salt := make([]byte, 32)
	startMessage := []byte("This is a random test message that must match forever and ever. Now adding messages to use more than one block. This is a random test message that must match forever and ever. This is a random test message that must match forever and ever. This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.This is a random test message that must match forever and ever.")
	cipherSha3 := NewEd25519Sha3BlockCipher(sender, recipient, nil)
	cipherSha2 := NewEd25519Sha2BlockCipher(sender, recipient, nil)
	encryptedSha3, err := cipherSha3.EncryptGCMNacl(startMessage, salt)
	assert.Nil(t, err)
	encryptedSha2, err := cipherSha2.EncryptGCMNacl(startMessage, salt)
	assert.Nil(t, err)
	decryptedSha3, err := cipherSha3.DecryptGCMNacl(encryptedSha3, salt)
	assert.Nil(t, err)
	decryptedSha2, err := cipherSha2.DecryptGCMNacl(encryptedSha2, salt)
	assert.Nil(t, err)
	assert.Equal(t, decryptedSha3, startMessage)
	assert.Equal(t, decryptedSha2, startMessage)
}

func TestDerivedKeyCompatNaCl(t *testing.T) {
	senderSha3, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha3Engine)
	assert.Nil(t, err)
	recipientSha3, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha3Engine)
	assert.Nil(t, err)
	senderSha2, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	recipientSha2, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
	salt := make([]byte, 32) //zeroed salt
	sharedKeySha3 := deriveSharedKey(senderSha3.PrivateKey, recipientSha3.PublicKey, salt, Ed25519Sha3)
	sharedKeySha32 := deriveSharedKey(recipientSha3.PrivateKey, senderSha3.PublicKey, salt, Ed25519Sha3)

	fmt.Printf("%x,%x", sharedKeySha3, sharedKeySha32)
	assert.Equal(t, sharedKeySha3, sharedKeySha32)

	sharedKeySha2 := deriveSharedKey(senderSha2.PrivateKey, recipientSha2.PublicKey, salt, Ed25519Sha2)
	sharedKeySha22 := deriveSharedKey(recipientSha2.PrivateKey, senderSha2.PublicKey, salt, Ed25519Sha2)

	fmt.Printf("%x,%x", sharedKeySha2, sharedKeySha22)
	assert.Equal(t, sharedKeySha2, sharedKeySha22)
}

func TestDerivedKeyCompatNaClMany(t *testing.T) {
	for i := 0; i < 20; i++ {
		senderSha3, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha3Engine)
		assert.Nil(t, err)
		recipientSha3, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha3Engine)
		assert.Nil(t, err)
		senderSha2, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
		assert.Nil(t, err)
		recipientSha2, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
		salt := make([]byte, 32) //zeroed salt
		sharedKeySha3 := deriveSharedKey(senderSha3.PrivateKey, recipientSha3.PublicKey, salt, Ed25519Sha3)
		sharedKeySha32 := deriveSharedKey(recipientSha3.PrivateKey, senderSha3.PublicKey, salt, Ed25519Sha3)

		fmt.Printf("%x,%x", sharedKeySha3, sharedKeySha32)
		assert.Equal(t, sharedKeySha3, sharedKeySha32)

		sharedKeySha2 := deriveSharedKey(senderSha2.PrivateKey, recipientSha2.PublicKey, salt, Ed25519Sha2)
		sharedKeySha22 := deriveSharedKey(recipientSha2.PrivateKey, senderSha2.PublicKey, salt, Ed25519Sha2)

		fmt.Printf("%x,%x", sharedKeySha2, sharedKeySha22)
		assert.Equal(t, sharedKeySha2, sharedKeySha22)
	}

}

func TestDerivedKeyCompatNaClFixedSha2(t *testing.T) {
	key, err := NewPrivateKeyfromHexString("2F985E4EC55D60C957C973BD1BEE2C0B3BA313A841D3EE4C74810805E6936053")
	assert.Nil(t, err)
	key2, err := NewPrivateKeyfromHexString("D6430327F90FAAD41F4BC69E51EB6C9D4C78B618D0A4B616478BD05E7A480950")
	assert.Nil(t, err)
	sender, err := NewKeyPair(key, nil, CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	recipient, _ := NewKeyPair(key2, nil, CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	sharedKey := deriveSharedKey(sender.PrivateKey, recipient.PublicKey, salt, Ed25519Sha2)
	sharedKey2 := deriveSharedKey(recipient.PrivateKey, sender.PublicKey, salt, Ed25519Sha2)
	fmt.Printf("%x,%x", sharedKey, sharedKey2)
	assert.Equal(t, sharedKey, sharedKey2)
}

func TestDerivedKeyCompatNaClFixedSha3(t *testing.T) {
	key, err := NewPrivateKeyfromHexString("2F985E4EC55D60C957C973BD1BEE2C0B3BA313A841D3EE4C74810805E6936053")
	assert.Nil(t, err)
	key2, err := NewPrivateKeyfromHexString("D6430327F90FAAD41F4BC69E51EB6C9D4C78B618D0A4B616478BD05E7A480950")
	assert.Nil(t, err)
	sender, err := NewKeyPair(key, nil, CryptoEngines.Ed25519Sha3Engine)
	assert.Nil(t, err)
	recipient, _ := NewKeyPair(key2, nil, CryptoEngines.Ed25519Sha3Engine)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	sharedKey := deriveSharedKey(sender.PrivateKey, recipient.PublicKey, salt, Ed25519Sha3)
	sharedKey2 := deriveSharedKey(recipient.PrivateKey, sender.PublicKey, salt, Ed25519Sha3)
	fmt.Printf("%x,%x", sharedKey, sharedKey2)
	assert.Equal(t, sharedKey, sharedKey2)
}
func TestDerivedKeyCompatNaClExpected(t *testing.T) {
	key, err := NewPublicKeyfromHex("9952DB28FF8186DD45F11A0BCD72872729D42098C03BE024FC3E7D5BC2BE40F1")
	assert.Nil(t, err)
	key2, err := NewPrivateKeyfromHexString("D6430327F90FAAD41F4BC69E51EB6C9D4C78B618D0A4B616478BD05E7A480950")
	assert.Nil(t, err)
	recipient, _ := NewKeyPair(key2, nil, CryptoEngines.Ed25519Sha3Engine)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	sharedKey := deriveSharedKey(recipient.PrivateKey, key, salt, Ed25519Sha3)
	fmt.Printf("%s \n", recipient.PublicKey.hex())
	fmt.Printf("%x", sharedKey)
	expected, err := hex.DecodeString("b05da9a74919f2e16aaa3270ced354a9d2b88c1b43588ddbc165ae62e147b057")
	assert.Nil(t, err)
	assert.Equal(t, sharedKey, expected)
}

func TestDerivedKeyCompatDefaultSha2(t *testing.T) {
	sender, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	recipient, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	cipher := NewEd25519Sha3BlockCipher(sender, recipient, nil)
	sharedKey, err := GetSharedKey(sender.PrivateKey, recipient.PublicKey, salt, cipher.keyLength, Ed25519Sha2)
	assert.Nil(t, err)
	sharedKey2, err := GetSharedKey(recipient.PrivateKey, sender.PublicKey, salt, cipher.keyLength, Ed25519Sha2)
	assert.Nil(t, err)
	assert.Equal(t, sharedKey, sharedKey2)
}

func TestDerivedKeyCompatDefaultSha3(t *testing.T) {
	sender, err := NewRandomKeyPair()
	assert.Nil(t, err)
	recipient, err := NewRandomKeyPair()
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	cipher := NewEd25519Sha3BlockCipher(sender, recipient, nil)
	sharedKey, err := GetSharedKey(sender.PrivateKey, recipient.PublicKey, salt, cipher.keyLength, Ed25519Sha3)
	assert.Nil(t, err)
	sharedKey2, err := GetSharedKey(recipient.PrivateKey, sender.PublicKey, salt, cipher.keyLength, Ed25519Sha3)
	assert.Nil(t, err)
	assert.Equal(t, sharedKey, sharedKey2)
}
func TestDerivedKeyCompatNaClMatchesDefaultEd25519Impl(t *testing.T) {
	sender, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	recipient, err := NewKeyPairByEngine(CryptoEngines.Ed25519Sha2Engine)
	assert.Nil(t, err)
	salt := make([]byte, 32) //zeroed salt
	cipher := NewEd25519Sha2BlockCipher(sender, recipient, nil)
	sharedKey, err := GetSharedKeyHkdf(sender.PrivateKey, recipient.PublicKey, salt, cipher.keyLength, Ed25519Sha2)
	assert.Nil(t, err)
	sharedKey2, err := GetSharedKeyHkdf(recipient.PrivateKey, sender.PublicKey, salt, cipher.keyLength, Ed25519Sha2)
	assert.Nil(t, err)
	sharedKey3 := deriveSharedKey(sender.PrivateKey, recipient.PublicKey, salt, Ed25519Sha2)
	sharedKey4 := deriveSharedKey(recipient.PrivateKey, sender.PublicKey, salt, Ed25519Sha2)
	fmt.Printf("%x,%x\n%x,%x", sharedKey, sharedKey2, sharedKey3, sharedKey4)
	assert.Equal(t, sharedKey, sharedKey2)
	assert.Equal(t, sharedKey3, sharedKey4)
	assert.Equal(t, sharedKey, sharedKey3)

}
