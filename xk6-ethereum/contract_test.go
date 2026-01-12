package ethereum

import (
	"math/big"
	"reflect"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
)

// makeUintType creates an ABI type for unsigned integers of the given bit size.
func makeUintType(size int) abi.Type {
	typ, _ := abi.NewType("uint"+strconv.Itoa(size), "", nil)

	return typ
}

// makeIntType creates an ABI type for signed integers of the given bit size.
func makeIntType(size int) abi.Type {
	typ, _ := abi.NewType("int"+strconv.Itoa(size), "", nil)

	return typ
}

func TestConvertBigIntToNative_UnsignedTypes(t *testing.T) {
	tests := []struct {
		name         string
		input        *big.Int
		abiType      abi.Type
		expectedType string
		expectError  bool
	}{
		{
			name:         "uint8 valid",
			input:        big.NewInt(255),
			abiType:      makeUintType(8),
			expectedType: "uint8",
		},
		{
			name:        "uint8 overflow",
			input:       big.NewInt(256),
			abiType:     makeUintType(8),
			expectError: true,
		},
		{
			name:         "uint16 valid",
			input:        big.NewInt(65535),
			abiType:      makeUintType(16),
			expectedType: "uint16",
		},
		{
			name:        "uint16 overflow",
			input:       big.NewInt(65536),
			abiType:     makeUintType(16),
			expectError: true,
		},
		{
			name:         "uint32 valid",
			input:        big.NewInt(4294967295),
			abiType:      makeUintType(32),
			expectedType: "uint32",
		},
		{
			name:        "uint32 overflow",
			input:       big.NewInt(4294967296),
			abiType:     makeUintType(32),
			expectError: true,
		},
		{
			name:         "uint64 valid",
			input:        new(big.Int).SetUint64(18446744073709551615),
			abiType:      makeUintType(64),
			expectedType: "uint64",
		},
		{
			name:        "uint64 overflow",
			input:       new(big.Int).Add(new(big.Int).SetUint64(18446744073709551615), big.NewInt(1)),
			abiType:     makeUintType(64),
			expectError: true,
		},
		{
			name:         "uint256 stays as big.Int",
			input:        new(big.Int).Exp(big.NewInt(2), big.NewInt(200), nil),
			abiType:      makeUintType(256),
			expectedType: "*big.Int",
		},
		{
			name:        "negative number for uint",
			input:       big.NewInt(-1),
			abiType:     makeUintType(64),
			expectError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := convertBigIntToNative(testCase.input, testCase.abiType)

			if testCase.expectError {
				require.Error(t, err)
				require.ErrorIs(t, err, errIntegerOverflow)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expectedType, reflect.TypeOf(result).String())
		})
	}
}

func TestConvertBigIntToNative_SignedTypes(t *testing.T) {
	tests := []struct {
		name         string
		input        *big.Int
		abiType      abi.Type
		expectedType string
		expectError  bool
	}{
		{
			name:         "int8 positive valid",
			input:        big.NewInt(127),
			abiType:      makeIntType(8),
			expectedType: "int8",
		},
		{
			name:         "int8 negative valid",
			input:        big.NewInt(-128),
			abiType:      makeIntType(8),
			expectedType: "int8",
		},
		{
			name:        "int8 overflow positive",
			input:       big.NewInt(128),
			abiType:     makeIntType(8),
			expectError: true,
		},
		{
			name:        "int8 overflow negative",
			input:       big.NewInt(-129),
			abiType:     makeIntType(8),
			expectError: true,
		},
		{
			name:         "int16 valid",
			input:        big.NewInt(32767),
			abiType:      makeIntType(16),
			expectedType: "int16",
		},
		{
			name:         "int32 valid",
			input:        big.NewInt(2147483647),
			abiType:      makeIntType(32),
			expectedType: "int32",
		},
		{
			name:         "int64 valid",
			input:        big.NewInt(9223372036854775807),
			abiType:      makeIntType(64),
			expectedType: "int64",
		},
		{
			name:         "int256 stays as big.Int",
			input:        new(big.Int).Exp(big.NewInt(2), big.NewInt(200), nil),
			abiType:      makeIntType(256),
			expectedType: "*big.Int",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := convertBigIntToNative(testCase.input, testCase.abiType)

			if testCase.expectError {
				require.Error(t, err)
				require.ErrorIs(t, err, errIntegerOverflow)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expectedType, reflect.TypeOf(result).String())
		})
	}
}

func TestConvertBigIntToNative_ValuePreserved(t *testing.T) {
	tests := []struct {
		name     string
		input    *big.Int
		abiType  abi.Type
		expected any
	}{
		{
			name:     "uint8 value preserved",
			input:    big.NewInt(42),
			abiType:  makeUintType(8),
			expected: uint8(42),
		},
		{
			name:     "uint64 value preserved",
			input:    big.NewInt(123456789),
			abiType:  makeUintType(64),
			expected: uint64(123456789),
		},
		{
			name:     "int8 negative preserved",
			input:    big.NewInt(-42),
			abiType:  makeIntType(8),
			expected: int8(-42),
		},
		{
			name:     "int64 value preserved",
			input:    big.NewInt(-123456789),
			abiType:  makeIntType(64),
			expected: int64(-123456789),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := convertBigIntToNative(testCase.input, testCase.abiType)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, result)
		})
	}
}
