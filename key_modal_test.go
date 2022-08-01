// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testPrivatKeyHex = "2275227522752275227522752275227522752275227522752275227522752275"
var testPrivatKeyBytes, _ = hex.DecodeString(testPrivatKeyHex)

func TestNewPrivateKey(t *testing.T) {
	val := testPrivatKeyHex
	key := NewPrivateKey(testPrivatKeyBytes)

	assertPrivateKey(t, key, val)
}

func assertPrivateKey(t *testing.T, key *PrivateKey, val string) {
	assert.Equal(t, val, key.String(), `key.Raw and NewBigInteger("%s").Bytes must by equal !`, val)
}

const testHexKeyValue = "227F227F227F227F227F227F227F227F227F227F227F227F227F227F227F227F"
const testHexPrivatKeyWrongLength = "ABC"
const testHexKeyMalformed = "227F227F227F227F227F227F227F227F227F227F227F227F227F227F227FXXXX"

func TestNewPrivatKeyfromHexString_WrongLength(t *testing.T) {
	_, err := NewPrivateKeyfromHexString(testHexPrivatKeyWrongLength)
	assert.Error(t, err)
}

func TestNewPrivatKeyfromHexString_Malformed(t *testing.T) {
	_, err := NewPrivateKeyfromHexString(testHexKeyMalformed)

	assert.Error(t, err)
}

// publicKey tests
var (
	testHexBytes = []byte{0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f, 0x22, 0x7f}
)

func TestNewPublicKey(t *testing.T) {
	key := NewPublicKey(testHexBytes)

	assert.Equal(t, testHexBytes, key.Raw, "not equal")
}

func TestNewPublicKeyfromHex(t *testing.T) {
	key, err := NewPublicKeyfromHex(testHexKeyValue)

	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, testHexBytes, key.Raw, "not equal")
}

func TestNewPublicKeyfromHex_Malformed(t *testing.T) {
	_, err := NewPublicKeyfromHex(testHexKeyMalformed)

	assert.Error(t, err)
}

func TestPublicKey_String(t *testing.T) {
	key := NewPublicKey(testHexBytes)

	assert.Equal(t, testHexKeyValue, key.String(), "wrong string")
}
