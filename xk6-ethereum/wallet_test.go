package ethereum

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAccountsFromMnemonic verifies HD derivation against known Anvil addresses.
func TestAccountsFromMnemonic(t *testing.T) {
	wallet := &Wallet{}

	// Standard Anvil test mnemonic.
	mnemonic := "test test test test test test test test test test test junk" //nolint:dupword

	// First 5 addresses derived from Anvil's mnemonic (m/44'/60'/0'/0/i).
	expectedAddresses := []string{
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		"0x90F79bf6EB2c4f870365E785982E1f101E93b906",
		"0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
	}

	keys, err := wallet.AccountsFromMnemonic(mnemonic, 5)
	require.NoError(t, err)
	require.Len(t, keys, 5)

	for i, expected := range expectedAddresses {
		require.Equal(t, expected, keys[i].Address, "address at index %d", i)
	}
}

// TestKeccak256 verifies against known hash values.
func TestKeccak256(t *testing.T) {
	wallet := &Wallet{}

	tests := []struct {
		name         string
		inputHex     string
		expectedHash string
	}{
		{
			// keccak256("") - well-known empty hash
			name:         "Empty input",
			inputHex:     "",
			expectedHash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			name:         "0x1234",
			inputHex:     "0x1234",
			expectedHash: "0x56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := wallet.Keccak256(tt.inputHex)
			require.NoError(t, err)
			require.Equal(t, tt.expectedHash, hash)
		})
	}
}

// TestComputeMappingSlot verifies storage slot computation for Solidity mappings.
// Formula: keccak256(abi.encode(key, baseSlot)).
func TestComputeMappingSlot(t *testing.T) {
	wallet := &Wallet{}

	tests := []struct {
		name         string
		key          string
		baseSlot     int64
		expectedSlot string
	}{
		{
			name:         "Anvil account 0 at slot 0",
			key:          "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			baseSlot:     0,
			expectedSlot: "0x723077b8a1b173adc35e5f0e7e3662fd1208212cb629f9c128551ea7168da722",
		},
		{
			name:         "Anvil account 1 at slot 0",
			key:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			baseSlot:     0,
			expectedSlot: "0x14e04a66bf74771820a7400ff6cf065175b3d7eb25805a5bd1633b161af5d101",
		},
		{
			name:         "Anvil account 0 at slot 1",
			key:          "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			baseSlot:     1,
			expectedSlot: "0xa3c1274aadd82e4d12c8004c33fb244ca686dad4fcc8957fc5668588c11d9502",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, err := wallet.ComputeMappingSlot(tt.key, tt.baseSlot)
			require.NoError(t, err)
			require.Equal(t, tt.expectedSlot, slot)
		})
	}
}

// TestComputeNestedMappingSlot verifies storage slot computation for nested mappings.
// Formula: keccak256(abi.encode(key2, keccak256(abi.encode(key1, baseSlot)))).
func TestComputeNestedMappingSlot(t *testing.T) {
	wallet := &Wallet{}

	tests := []struct {
		name         string
		key1         string
		key2         string
		baseSlot     int64
		expectedSlot string
	}{
		{
			name:         "account0 -> account1 at slot 1",
			key1:         "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			key2:         "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			baseSlot:     1,
			expectedSlot: "0x7bb4c14a4642c37aac43229fec930a0666790858dbac8fc0f7b91e6a34742718",
		},
		{
			name:         "account1 -> account0 at slot 1",
			key1:         "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			key2:         "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			baseSlot:     1,
			expectedSlot: "0xb300b9f82ae3c9e09a60daf61274f993398c953da16aad2e815fbb2b650d2ec2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, err := wallet.ComputeNestedMappingSlot(tt.key1, tt.key2, tt.baseSlot)
			require.NoError(t, err)
			require.Equal(t, tt.expectedSlot, slot)
		})
	}
}

// TestComputeNestedMappingSlot_KeyOrderMatters verifies that swapping keys produces different slots.
func TestComputeNestedMappingSlot_KeyOrderMatters(t *testing.T) {
	wallet := &Wallet{}

	key1 := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" //gitleaks:allow
	key2 := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" //gitleaks:allow

	slot1, err := wallet.ComputeNestedMappingSlot(key1, key2, 1)
	require.NoError(t, err)

	slot2, err := wallet.ComputeNestedMappingSlot(key2, key1, 1)
	require.NoError(t, err)

	require.NotEqual(t, slot1, slot2)
}
