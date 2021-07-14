package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashesSha_256(t *testing.T) {
	const proof = "36e82fd88dbd06c07effe09ac6a652aca2b111b653d05429df494ad958273098"

	secretB, err := HashesSha_256([]byte(proof))
	assert.Nil(t, err)

	assert.Equal(t, "c346f5ecf5bcfa54ab14fad815c8239bdeb051df8835d212dba2af59f688a00e", hex.EncodeToString(secretB))
}

func TestHashesKeccak_256(t *testing.T) {
	const proof = "B778A39A3663719DFC5E48C9D78431B1E45C2AF9DF538782BF199C189DABEAC7"

	proofB, err := hex.DecodeString(proof)
	secretB, err := HashesKeccak_256(proofB)
	assert.Nil(t, err)

	assert.Equal(t, "241c1d54c18c8422def03aa16b4b243a8ba491374295a1a6965545e6ac1af314", hex.EncodeToString(secretB))
}

func TestHashesSha3_256(t *testing.T) {
	const proof = "B778A39A3663719DFC5E48C9D78431B1E45C2AF9DF538782BF199C189DABEAC7"

	proofB, err := hex.DecodeString(proof)
	secretB, err := HashesSha3_256(proofB)
	assert.Nil(t, err)

	assert.Equal(t, "9b3155b37159da50aa52d5967c509b410f5a36a3b1e31ecb5ac76675d79b4a5e", hex.EncodeToString(secretB))
}

func TestHashesSha3_512(t *testing.T) {
	const proof = "B778A39A3663719DFC5E48C9D78431B1E45C2AF9DF538782BF199C189DABEAC7680ADA57" +
		"DCEC8EEE91C4E3BF3BFA9AF6FFDE90CD1D249D1C6121D7B759A001B1"

	proofB, err := hex.DecodeString(proof)
	secretB, err := HashesSha3_512(proofB)
	assert.Nil(t, err)

	assert.Equal(t, "d23859866f93f2698a5b48586543c608d85a57c74e9ce92d86a0b25065d"+
		"8155c16754d840026b8c536f2bcb963a7d867f034ec241b87162ac33daf7b707cb5f7", hex.EncodeToString(secretB))
}

func TestHashesRipemd160(t *testing.T) {
	const proof = "8ed368fe7077da578f72785771529a407d3c40e70fff0f70723a34d8d1a643ce"

	secretB, err := HashesRipemd160([]byte(proof))
	assert.Nil(t, err)

	assert.Equal(t, "3fc43d717d824302e3821de8129ea2f7786912e5", hex.EncodeToString(secretB))
}

func TestEncryptDecryptGCM(t *testing.T) {
	sender, _ := NewRandomKeyPair()
	recipient, _ := NewRandomKeyPair()
	iv := MathUtils.GetRandomByteArray(12)
	encoded, err := encodeMessage(*sender.PrivateKey, *recipient.PublicKey, "This is a random test message that must match forever and ever.", iv)
	if err != nil {
		panic(fmt.Sprintf("Unable to encode message: %s", err))
	}
	decoded, err := decodeMessage(*recipient.PrivateKey, *sender.PublicKey, encoded, iv)
	if err != nil {
		panic(fmt.Sprintf("Unable to decode message: %s", err))
	}
	fmt.Print(decoded)
}

func TestDerivedKeyCompat(t *testing.T) {
	sender, _ := NewRandomKeyPair()
	recipient, _ := NewRandomKeyPair()
	sharedKey := deriveSharedKey(sender.PrivateKey.Raw, recipient.PublicKey.Raw)
	sharedKey2 := deriveSharedKey(recipient.PrivateKey.Raw, sender.PublicKey.Raw)
	fmt.Printf("a %s\n", sender.PrivateKey.String())
	fmt.Printf("b %s\n", recipient.PrivateKey.String())
	fmt.Printf("a %x", sharedKey)
	fmt.Printf("b %x", sharedKey2)
	assert.Equal(t, sharedKey, sharedKey2)
}

func TestDerivedKeyCompatFixedKeys(t *testing.T) {
	senderpriv, _ := NewPrivateKeyfromHexString("4d4296a0520fbddca4e1646fc0a9f925a3393dbc535a0c41f01057bedb5f4f64")
	receiverpriv, _ := NewPrivateKeyfromHexString("c6638ba0981161967b67e9f45eca27b3d94c4261dece9c93259879824cc176b4")
	sender, _ := NewKeyPair(senderpriv, nil, nil)
	recipient, _ := NewKeyPair(receiverpriv, nil, nil)
	sharedKey := deriveSharedKey(sender.PrivateKey.Raw, recipient.PublicKey.Raw)
	sharedKey2 := deriveSharedKey(recipient.PrivateKey.Raw, sender.PublicKey.Raw)
	fmt.Printf("a %s\n", sender.PrivateKey.String())
	fmt.Printf("b %s\n", recipient.PrivateKey.String())
	fmt.Printf("a %x", sharedKey)
	fmt.Printf("b %x", sharedKey2)
	assert.Equal(t, sharedKey, sharedKey2)
}
