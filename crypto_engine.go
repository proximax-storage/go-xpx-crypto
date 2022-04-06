// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package crypto

// Represents a key derivation scheme associated with a given crypto engine
type DerivationScheme uint32

const (
	Unset       DerivationScheme = iota
	Ed25519Sha3 DerivationScheme = iota
	Ed25519Sha2 DerivationScheme = iota
)

// CryptoEngine represents a cryptographic engine that is a factory of crypto-providers.
type CryptoEngine interface {
	// Creates a DSA signer.
	CreateDsaSigner(keyPair *KeyPair) DsaSigner
	// Creates a key generator.
	CreateKeyGenerator() KeyGenerator
	// Creates a block cipher.
	CreateBlockCipher(senderKeyPair *KeyPair, recipientKeyPair *KeyPair) BlockCipher
	// Creates a key analyzer.
	CreateKeyAnalyzer() KeyAnalyzer
	// Returns the engine's derivation scheme
	EngineDerivationScheme() DerivationScheme
}

// cryptoEngines Static class that exposes crypto engines.
type cryptoEngines struct {
	Ed25519Sha2Engine *Ed25519Sha2SeedCryptoEngine
	Ed25519Sha3Engine *Ed25519Sha3SeedCryptoEngine
	DefaultEngine     CryptoEngine
}

// CryptoEngines has cryptographic engines
var CryptoEngines = cryptoEngines{
	&Ed25519Sha2SeedCryptoEngine{nil},
	&Ed25519Sha3SeedCryptoEngine{nil},
	&Ed25519Sha3SeedCryptoEngine{nil},
}

func DefaultEngine() CryptoEngine {
	return CryptoEngines.DefaultEngine
}

func SetDefaultEngine(engine CryptoEngine) {
	CryptoEngines.DefaultEngine = engine
}
