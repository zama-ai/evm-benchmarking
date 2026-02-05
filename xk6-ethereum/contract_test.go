package ethereum

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
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

func TestParseReceiptEvents(t *testing.T) {
	const testABI = `[{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":false,"name":"value","type":"uint256"},{"indexed":false,"name":"payload","type":"bytes"}],"name":"CustomTransfer","type":"event"}]`

	contractABI, err := abi.JSON(strings.NewReader(testABI))
	require.NoError(t, err)

	contractAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	contract := &Contract{
		abi:  &contractABI,
		addr: contractAddr,
	}

	event := contractABI.Events["CustomTransfer"]
	value := big.NewInt(42)
	payload := []byte{0x01, 0x02}

	data, err := event.Inputs.NonIndexed().Pack(value, payload)
	require.NoError(t, err)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	fromTopic := common.BytesToHash(common.LeftPadBytes(from.Bytes(), 32))

	receipt := &Receipt{
		Logs: []*Log{
			{
				Address: contractAddr.Hex(),
				Topics:  []string{event.ID.Hex(), fromTopic.Hex()},
				Data:    "0x" + hex.EncodeToString(data),
			},
		},
	}

	parsed, err := contract.ParseReceiptEvents(receipt)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	evt := parsed[0]
	require.Equal(t, "CustomTransfer", evt.Name)
	require.Equal(t, event.Sig, evt.Signature)
	require.Equal(t, contractAddr.Hex(), evt.Address)

	require.Equal(t, from.Hex(), evt.Args["from"])
	require.Equal(t, "42", evt.Args["value"])
	require.Equal(t, "0x0102", evt.Args["payload"])
}

func TestParseReceiptEvents_AuctionEvents(t *testing.T) {
	const auctionEventsABI = `[
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "bidId", "type": "uint256"},
				{"indexed": true, "name": "bidder", "type": "address"},
				{"indexed": false, "name": "eQuantity", "type": "bytes32"},
				{"indexed": false, "name": "price", "type": "uint64"},
				{"indexed": false, "name": "ePaid", "type": "bytes32"}
			],
			"name": "BidSubmitted",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "user", "type": "address"},
				{"indexed": false, "name": "allocation", "type": "uint256"}
			],
			"name": "ZamaTokenDistributed",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "user", "type": "address"},
				{"indexed": false, "name": "eTotalRefundAmount", "type": "bytes32"}
			],
			"name": "TokenRefunded",
			"type": "event"
		}
	]`

	contractABI, err := abi.JSON(strings.NewReader(auctionEventsABI))
	require.NoError(t, err)

	contractAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	contract := &Contract{
		abi:  &contractABI,
		addr: contractAddr,
	}

	// Build test data for each event type.
	bidEvent := contractABI.Events["BidSubmitted"]
	bidID := big.NewInt(42)
	bidder := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	price := uint64(100)

	var eQuantity, ePaid [32]byte

	copy(eQuantity[:], []byte{0xaa, 0xbb, 0xcc})
	copy(ePaid[:], []byte{0xdd, 0xee, 0xff})

	bidLog := buildBidLog(t, contractAddr, bidEvent, bidID, bidder, eQuantity, price, ePaid)

	distributionEvent := contractABI.Events["ZamaTokenDistributed"]
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	allocation := big.NewInt(1000000)

	distLog := buildDistributionLog(t, contractAddr, distributionEvent, user, allocation)

	refundEvent := contractABI.Events["TokenRefunded"]

	var refundAmount [32]byte

	copy(refundAmount[:], []byte{0x11, 0x22, 0x33})

	refundLog := buildRefundLog(t, contractAddr, refundEvent, user, refundAmount)

	// Parse the receipt containing all three event logs.
	receipt := &Receipt{Logs: []*Log{bidLog, distLog, refundLog}}
	parsed, err := contract.ParseReceiptEvents(receipt)
	require.NoError(t, err)
	require.Len(t, parsed, 3)

	t.Run("BidSubmitted", func(t *testing.T) {
		require.Equal(t, "BidSubmitted", parsed[0].Name)
		require.Equal(t, bidder.Hex(), parsed[0].Args["bidder"])
		require.Equal(t, "42", parsed[0].Args["bidId"])
		require.Equal(t, price, parsed[0].Args["price"])
		require.Equal(t, "0x"+hex.EncodeToString(eQuantity[:]), parsed[0].Args["eQuantity"])
		require.Equal(t, "0x"+hex.EncodeToString(ePaid[:]), parsed[0].Args["ePaid"])
	})

	t.Run("ZamaTokenDistributed", func(t *testing.T) {
		require.Equal(t, "ZamaTokenDistributed", parsed[1].Name)
		require.Equal(t, user.Hex(), parsed[1].Args["user"])
		require.Equal(t, "1000000", parsed[1].Args["allocation"])
	})

	t.Run("TokenRefunded", func(t *testing.T) {
		require.Equal(t, "TokenRefunded", parsed[2].Name)
		require.Equal(t, user.Hex(), parsed[2].Args["user"])
		require.Equal(t, "0x"+hex.EncodeToString(refundAmount[:]), parsed[2].Args["eTotalRefundAmount"])
	})
}

func buildBidLog(
	t *testing.T,
	contractAddr common.Address,
	bidEvent abi.Event,
	bidID *big.Int,
	bidder common.Address,
	eQuantity [32]byte,
	price uint64,
	ePaid [32]byte,
) *Log {
	t.Helper()

	bidData, err := bidEvent.Inputs.NonIndexed().Pack(eQuantity, price, ePaid)
	require.NoError(t, err)

	return &Log{
		Address: contractAddr.Hex(),
		Topics: []string{
			bidEvent.ID.Hex(),
			common.BigToHash(bidID).Hex(),
			common.BytesToHash(common.LeftPadBytes(bidder.Bytes(), 32)).Hex(),
		},
		Data: "0x" + hex.EncodeToString(bidData),
	}
}

func buildDistributionLog(
	t *testing.T,
	contractAddr common.Address,
	event abi.Event,
	user common.Address,
	allocation *big.Int,
) *Log {
	t.Helper()

	data, err := event.Inputs.NonIndexed().Pack(allocation)
	require.NoError(t, err)

	return &Log{
		Address: contractAddr.Hex(),
		Topics: []string{
			event.ID.Hex(),
			common.BytesToHash(common.LeftPadBytes(user.Bytes(), 32)).Hex(),
		},
		Data: "0x" + hex.EncodeToString(data),
	}
}

func buildRefundLog(
	t *testing.T,
	contractAddr common.Address,
	event abi.Event,
	user common.Address,
	refundAmount [32]byte,
) *Log {
	t.Helper()

	data, err := event.Inputs.NonIndexed().Pack(refundAmount)
	require.NoError(t, err)

	return &Log{
		Address: contractAddr.Hex(),
		Topics: []string{
			event.ID.Hex(),
			common.BytesToHash(common.LeftPadBytes(user.Bytes(), 32)).Hex(),
		},
		Data: "0x" + hex.EncodeToString(data),
	}
}
