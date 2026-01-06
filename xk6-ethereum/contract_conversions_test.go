package ethereum

import (
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestConvertArgsMethodAndCountValidation(t *testing.T) {
	abiStr := `[{"type":"function","name":"foo","inputs":[{"name":"amount","type":"uint256"},{"name":"to","type":"address"}],"outputs":[]}]`
	contractABI, err := abi.JSON(strings.NewReader(abiStr))
	require.NoError(t, err)

	_, err = convertArgs(&contractABI, "bar", []any{})
	require.ErrorIs(t, err, errMethodNotFound)

	_, err = convertArgs(&contractABI, "foo", []any{int64(1)})
	require.ErrorIs(t, err, errInvalidArgCount)
}

func TestConvertNumber(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    *big.Int
		wantErr bool
	}{
		{name: "int", input: int(7), want: big.NewInt(7)},
		{name: "int64", input: int64(-3), want: big.NewInt(-3)},
		{name: "uint64", input: uint64(42), want: new(big.Int).SetUint64(42)},
		{name: "floatIntegral", input: float64(10), want: big.NewInt(10)},
		{name: "floatFractional", input: float64(1.5), wantErr: true},
		{name: "floatNaN", input: math.NaN(), wantErr: true},
		{name: "floatInf", input: math.Inf(1), wantErr: true},
		{name: "stringDecimal", input: "123", want: big.NewInt(123)},
		{name: "stringHex", input: "0x10", want: big.NewInt(16)},
		{name: "stringEmpty", input: "  ", wantErr: true},
		{name: "stringInvalid", input: "0xzz", wantErr: true},
		{name: "bigIntPtr", input: big.NewInt(9), want: big.NewInt(9)},
		{name: "bigIntValue", input: *big.NewInt(11), want: big.NewInt(11)},
		{name: "floatOutOfRange", input: float64(maxSafeInt) + 1, wantErr: true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := convertNumber(testCase.input)
			if testCase.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, 0, result.Cmp(testCase.want))
		})
	}
}

func TestConvertAddress(t *testing.T) {
	addr, err := convertAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	require.NoError(t, err)
	require.Equal(t, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), addr)

	_, err = convertAddress(123)
	require.ErrorIs(t, err, errInvalidAddressType)
}

func TestConvertBytesAndDecodeHexString(t *testing.T) {
	bytesVal, err := convertBytes("0x0")
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, bytesVal)

	bytesVal, err = convertBytes("abcd")
	require.NoError(t, err)
	require.Equal(t, []byte{0xab, 0xcd}, bytesVal)

	_, err = convertBytes(123)
	require.ErrorIs(t, err, errInvalidBytesType)

	_, err = decodeHexString("0xzz")
	require.Error(t, err)
}

func TestConvertSequenceFixedArrayAndSlice(t *testing.T) {
	fixedType, err := abi.NewType("uint256[2]", "", nil)
	require.NoError(t, err)

	_, err = convertSequence([]any{int64(1)}, fixedType)
	require.ErrorIs(t, err, errInvalidArrayLength)

	result, err := convertSequence([]any{int64(1), int64(2)}, fixedType)
	require.NoError(t, err)

	value := reflect.ValueOf(result)
	require.Equal(t, 2, value.Len())

	firstElement, isBigInt := value.Index(0).Interface().(*big.Int)
	require.True(t, isBigInt)
	require.Equal(t, int64(1), firstElement.Int64())

	sliceType, err := abi.NewType("address[]", "", nil)
	require.NoError(t, err)

	result, err = convertSequence([]any{
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
	}, sliceType)
	require.NoError(t, err)

	addresses, isAddressSlice := result.([]common.Address)
	require.True(t, isAddressSlice)
	require.Len(t, addresses, 2)
}

func TestConvertTuple(t *testing.T) {
	tupleType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "addr", Type: "address"},
		{Name: "amount", Type: "uint256"},
	})
	require.NoError(t, err)

	result, err := convertTuple([]any{
		"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		int64(7),
	}, tupleType)
	require.NoError(t, err)

	reflectValue := reflect.ValueOf(result)
	require.Equal(t, tupleType.GetType(), reflectValue.Type())

	addr, ok := reflectValue.Field(0).Interface().(common.Address)
	require.True(t, ok)
	require.Equal(t, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), addr)

	amount, ok := reflectValue.Field(1).Interface().(*big.Int)
	require.True(t, ok)
	require.Equal(t, int64(7), amount.Int64())

	_, err = convertTuple("not-a-tuple", tupleType)
	require.ErrorIs(t, err, errInvalidTupleType)

	_, err = convertTuple([]any{int64(1)}, tupleType)
	require.ErrorIs(t, err, errInvalidTupleType)
}

func TestConvertValueFixedBytesLengthMismatch(t *testing.T) {
	fixedBytes, err := abi.NewType("bytes4", "", nil)
	require.NoError(t, err)

	_, err = convertValue("0x0102", fixedBytes)
	require.ErrorIs(t, err, errInvalidFixedByteArraySize)
}

func TestParseHexAddressAndSafeInt64FromUint64(t *testing.T) {
	_, err := parseHexAddress("not-an-address")
	require.ErrorIs(t, err, errInvalidAddress)

	addr, err := parseHexAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	require.NoError(t, err)
	require.Equal(t, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), addr)

	_, err = safeInt64FromUint64(uint64(maxInt64) + 1)
	require.ErrorIs(t, err, errValueOverflow)

	value, err := safeInt64FromUint64(uint64(maxInt64))
	require.NoError(t, err)
	require.Equal(t, maxInt64, value)
}
