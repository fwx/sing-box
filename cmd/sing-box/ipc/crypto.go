package ipc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// RFC 3526 Group 14 (2048-bit MODP Group)
// https://www.rfc-editor.org/rfc/rfc3526#section-3
var (
	dhPrime = func() *big.Int {
		primeHex := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
		p, _ := new(big.Int).SetString(primeHex, 16)
		return p
	}()
	dhGenerator = big.NewInt(2)
)

const (
	// Key sizes
	DHPublicKeySize = 256 // 2048 bits = 256 bytes
	AESKeySize      = 32  // AES-256
	HMACKeySize     = 32  // HMAC-SHA256
	NonceSize       = 32  // Challenge nonce size
	GCMIVSize       = 12  // AES-GCM IV size
	GCMTagSize      = 16  // AES-GCM authentication tag size

	// HKDF salt and info strings
	hkdfSalt           = "LoopVPN_SingBox_v1"
	hkdfInfoEncryption = "encryption"
	hkdfInfoAuth       = "authentication"
)

// KeyExchange handles Diffie-Hellman key exchange and derived key management
type KeyExchange struct {
	privateKey   *big.Int
	publicKey    []byte
	sharedSecret []byte
	aesKey       []byte
	hmacKey      []byte
}

// NewKeyExchange creates a new KeyExchange instance and generates a keypair
func NewKeyExchange() (*KeyExchange, error) {
	k := &KeyExchange{}
	if err := k.GenerateKeyPair(); err != nil {
		return nil, err
	}
	return k, nil
}

// GenerateKeyPair generates a new DH keypair
func (k *KeyExchange) GenerateKeyPair() error {
	// Generate random private key (256 bytes for 2048-bit group)
	privateBytes := make([]byte, DHPublicKeySize)
	if _, err := io.ReadFull(rand.Reader, privateBytes); err != nil {
		return err
	}

	k.privateKey = new(big.Int).SetBytes(privateBytes)
	// Ensure private key is in valid range: 1 < x < p-1
	k.privateKey.Mod(k.privateKey, new(big.Int).Sub(dhPrime, big.NewInt(2)))
	k.privateKey.Add(k.privateKey, big.NewInt(2))

	// Compute public key: g^x mod p
	pubKeyBig := new(big.Int).Exp(dhGenerator, k.privateKey, dhPrime)

	// Pad public key to fixed size
	pubKeyBytes := pubKeyBig.Bytes()
	k.publicKey = make([]byte, DHPublicKeySize)
	copy(k.publicKey[DHPublicKeySize-len(pubKeyBytes):], pubKeyBytes)

	return nil
}

// GetPublicKey returns the DH public key (256 bytes)
func (k *KeyExchange) GetPublicKey() []byte {
	result := make([]byte, len(k.publicKey))
	copy(result, k.publicKey)
	return result
}

// ComputeSharedSecret computes the shared secret from peer's public key
func (k *KeyExchange) ComputeSharedSecret(peerPublicKey []byte) error {
	if len(peerPublicKey) != DHPublicKeySize {
		return errors.New("invalid peer public key size")
	}

	peerPubBig := new(big.Int).SetBytes(peerPublicKey)

	// Validate peer public key: 1 < y < p-1
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(dhPrime, one)
	if peerPubBig.Cmp(one) <= 0 || peerPubBig.Cmp(pMinus1) >= 0 {
		return errors.New("invalid peer public key value")
	}

	// Compute shared secret: y^x mod p
	sharedBig := new(big.Int).Exp(peerPubBig, k.privateKey, dhPrime)

	// Pad shared secret to fixed size
	sharedBytes := sharedBig.Bytes()
	k.sharedSecret = make([]byte, DHPublicKeySize)
	copy(k.sharedSecret[DHPublicKeySize-len(sharedBytes):], sharedBytes)

	return nil
}

// DeriveKeys derives AES and HMAC keys from the shared secret using HKDF
func (k *KeyExchange) DeriveKeys() error {
	if len(k.sharedSecret) == 0 {
		return errors.New("shared secret not computed")
	}

	salt := []byte(hkdfSalt)

	// Derive AES key
	aesHKDF := hkdf.New(sha256.New, k.sharedSecret, salt, []byte(hkdfInfoEncryption))
	k.aesKey = make([]byte, AESKeySize)
	if _, err := io.ReadFull(aesHKDF, k.aesKey); err != nil {
		return err
	}

	// Derive HMAC key
	hmacHKDF := hkdf.New(sha256.New, k.sharedSecret, salt, []byte(hkdfInfoAuth))
	k.hmacKey = make([]byte, HMACKeySize)
	if _, err := io.ReadFull(hmacHKDF, k.hmacKey); err != nil {
		return err
	}

	return nil
}

// GetAESKey returns the derived AES key
func (k *KeyExchange) GetAESKey() []byte {
	result := make([]byte, len(k.aesKey))
	copy(result, k.aesKey)
	return result
}

// GetHMACKey returns the derived HMAC key
func (k *KeyExchange) GetHMACKey() []byte {
	result := make([]byte, len(k.hmacKey))
	copy(result, k.hmacKey)
	return result
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns: IV (12 bytes) + ciphertext + tag (16 bytes)
func (k *KeyExchange) Encrypt(plaintext []byte) ([]byte, error) {
	if len(k.aesKey) == 0 {
		return nil, errors.New("AES key not derived")
	}

	block, err := aes.NewCipher(k.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, GCMIVSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt with GCM (appends auth tag)
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Prepend IV
	result := make([]byte, GCMIVSize+len(ciphertext))
	copy(result[:GCMIVSize], iv)
	copy(result[GCMIVSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
// Input: IV (12 bytes) + ciphertext + tag (16 bytes)
func (k *KeyExchange) Decrypt(data []byte) ([]byte, error) {
	if len(k.aesKey) == 0 {
		return nil, errors.New("AES key not derived")
	}

	if len(data) < GCMIVSize+GCMTagSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(k.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := data[:GCMIVSize]
	ciphertext := data[GCMIVSize:]

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ComputeHMAC computes HMAC-SHA256 of the given data
func (k *KeyExchange) ComputeHMAC(data []byte) []byte {
	h := hmac.New(sha256.New, k.hmacKey)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256 of the given data
func (k *KeyExchange) VerifyHMAC(data, expectedMAC []byte) bool {
	actualMAC := k.ComputeHMAC(data)
	return hmac.Equal(actualMAC, expectedMAC)
}

// GenerateNonce generates a random nonce for challenge-response authentication
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// SharedSecretHex returns the shared secret as a hex string (for debugging)
func (k *KeyExchange) SharedSecretHex() string {
	return hex.EncodeToString(k.sharedSecret)
}
