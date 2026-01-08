package ethereum

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
	"go.k6.io/k6/js/modules"
)

// Static errors for wallet operations.
var (
	errInvalidPrivateKeyLength = errors.New("invalid private key: expected hex string with even length")
	errEmptyPrivateKey         = errors.New("invalid private key: empty bytes")
)

// Default account count for mnemonic derivation.
const defaultAccountCount = 10

// Wallet provides wallet operations for k6 scripts.
type Wallet struct{}

// Key represents an Ethereum key pair.
type Key struct {
	PrivateKey string `js:"privateKey"`
	Address    string `js:"address"`
}

// DerivationPath represents a BIP-32/44 derivation path.
// Standard Ethereum path: m/44'/60'/0'/0/index.
type DerivationPath []uint32

// DefaultDerivationPath is the standard Ethereum derivation path.
//
//nolint:gochecknoglobals // Standard constant path.
var DefaultDerivationPath = DerivationPath{
	0x80000000 + 44, // 44' (purpose)
	0x80000000 + 60, // 60' (coin type for Ethereum)
	0x80000000 + 0,  // 0'  (account)
	0,               // 0   (change)
	0,               // 0   (address index)
}

func init() { //nolint:gochecknoinits // Required for k6 module registration.
	walletModule := Wallet{}
	modules.Register("k6/x/ethereum/wallet", &walletModule)
}

// GenerateKey creates a random Ethereum key pair.
func (w *Wallet) GenerateKey() (*Key, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &Key{
		PrivateKey: hex.EncodeToString(privateKeyBytes),
		Address:    address.Hex(),
	}, nil
}

// AccountsFromMnemonic derives a list of accounts from a BIP-39 mnemonic.
// It uses the standard Ethereum path m/44'/60'/0'/0/i, starting at index 0.
// If count <= 0, it defaults to 10 accounts.
func (w *Wallet) AccountsFromMnemonic(mnemonic string, count int) ([]Key, error) {
	effectiveCount := count
	if effectiveCount <= 0 {
		effectiveCount = defaultAccountCount
	}

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create seed from mnemonic: %w", err)
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	keys := make([]Key, 0, effectiveCount)

	for index := range effectiveCount {
		// Copy default derivation path and set the last index.
		path := make(DerivationPath, len(DefaultDerivationPath))
		copy(path, DefaultDerivationPath)
		path[len(path)-1] = uint32(index) //nolint:gosec // Index is bounded by effectiveCount.

		derivedKey, deriveErr := deriveKey(masterKey, path)
		if deriveErr != nil {
			return nil, fmt.Errorf("failed to derive key at index %d: %w", index, deriveErr)
		}

		privateKey, privKeyErr := derivedKey.ECPrivKey()
		if privKeyErr != nil {
			return nil, fmt.Errorf("failed to get private key at index %d: %w", index, privKeyErr)
		}

		ecdsaKey := privateKey.ToECDSA()
		privateKeyBytes := crypto.FromECDSA(ecdsaKey)
		address := crypto.PubkeyToAddress(ecdsaKey.PublicKey)

		keys = append(keys, Key{
			PrivateKey: hex.EncodeToString(privateKeyBytes),
			Address:    address.Hex(),
		})
	}

	return keys, nil
}

// deriveKey derives a key from a master key using a derivation path.
func deriveKey(masterKey *hdkeychain.ExtendedKey, path DerivationPath) (*hdkeychain.ExtendedKey, error) {
	var err error

	key := masterKey

	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, fmt.Errorf("failed to derive: %w", err)
		}
	}

	return key, nil
}

// AccountFromPrivateKey constructs an account from a hex-encoded private key
// and derives its address. The input may be with or without a leading 0x.
func (w *Wallet) AccountFromPrivateKey(privateKeyHex string) (*Key, error) {
	cleaned := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(privateKeyHex)), "0x")
	if len(cleaned) == 0 || len(cleaned)%2 != 0 {
		return nil, errInvalidPrivateKeyLength
	}

	rawKey, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	if len(rawKey) == 0 {
		return nil, errEmptyPrivateKey
	}

	privateKey, err := crypto.ToECDSA(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet from private key: %w", err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &Key{
		PrivateKey: hex.EncodeToString(privateKeyBytes),
		Address:    address.Hex(),
	}, nil
}

// Keccak256 computes the Keccak-256 hash of the input hex string.
// Input can be with or without 0x prefix. Returns 0x-prefixed hash.
func (w *Wallet) Keccak256(inputHex string) (string, error) {
	data, err := hex.DecodeString(strings.TrimPrefix(inputHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("failed to decode hex input: %w", err)
	}

	return crypto.Keccak256Hash(data).Hex(), nil
}

// ABI types for encoding mapping keys.
//
//nolint:gochecknoglobals // ABI types are constant and safe to reuse.
var (
	abiAddress, _ = abi.NewType("address", "", nil)
	abiUint256, _ = abi.NewType("uint256", "", nil)
	abiBytes32, _ = abi.NewType("bytes32", "", nil)
)

// ComputeMappingSlot computes the storage slot for a Solidity mapping entry.
// For mapping(address => T) at baseSlot, the slot for key is keccak256(abi.encode(key, baseSlot)).
func (w *Wallet) ComputeMappingSlot(key string, baseSlot int64) (string, error) {
	addr, err := parseHexAddress(key)
	if err != nil {
		return "", err
	}

	args := abi.Arguments{
		{Type: abiAddress},
		{Type: abiUint256},
	}

	encoded, err := args.Pack(addr, big.NewInt(baseSlot))
	if err != nil {
		return "", fmt.Errorf("failed to encode mapping slot: %w", err)
	}

	return crypto.Keccak256Hash(encoded).Hex(), nil
}

// ComputeNestedMappingSlot computes the storage slot for a nested Solidity mapping.
// For mapping(address => mapping(address => T)) at baseSlot,
// the slot for [key1][key2] is keccak256(abi.encode(key2, keccak256(abi.encode(key1, baseSlot)))).
func (w *Wallet) ComputeNestedMappingSlot(key1, key2 string, baseSlot int64) (string, error) {
	addr1, err := parseHexAddress(key1)
	if err != nil {
		return "", err
	}

	addr2, err := parseHexAddress(key2)
	if err != nil {
		return "", err
	}

	// Compute intermediate slot: keccak256(abi.encode(key1, baseSlot))
	args1 := abi.Arguments{
		{Type: abiAddress},
		{Type: abiUint256},
	}

	encoded1, err := args1.Pack(addr1, big.NewInt(baseSlot))
	if err != nil {
		return "", fmt.Errorf("failed to encode first mapping: %w", err)
	}

	intermediateSlot := crypto.Keccak256Hash(encoded1)

	// Compute final slot: keccak256(abi.encode(key2, intermediateSlot))
	args2 := abi.Arguments{
		{Type: abiAddress},
		{Type: abiBytes32},
	}

	encoded2, err := args2.Pack(addr2, intermediateSlot)
	if err != nil {
		return "", fmt.Errorf("failed to encode nested mapping: %w", err)
	}

	return crypto.Keccak256Hash(encoded2).Hex(), nil
}
