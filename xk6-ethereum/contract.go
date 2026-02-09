package ethereum

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Static errors for contract operations.
var (
	errContractNotInitialized    = errors.New("contract not initialized")
	errMethodNotFound            = errors.New("method not found in ABI")
	errInvalidArgCount           = errors.New("invalid arg count")
	errInvalidFixedByteArraySize = errors.New("expected fixed byte array size mismatch")
	errInvalidTupleType          = errors.New("expected tuple compatible type")
	errInvalidArrayType          = errors.New("expected array type")
	errInvalidArrayLength        = errors.New("expected array length mismatch")
	errInvalidAddressType        = errors.New("expected address type")
	errInvalidNumberType         = errors.New("expected number or string type")
	errInvalidBytesType          = errors.New("expected hex string or bytes type")
	errIntegerOverflow           = errors.New("integer overflow")
	errReceiptRequired           = errors.New("receipt is required")
	errMissingEventSignature     = errors.New("missing event signature topic")
)

const (
	maxSafeInt = 9007199254740991
	minSafeInt = -9007199254740991
)

// Contract exposes a contract.
type Contract struct {
	abi    *abi.ABI
	client *Client
	addr   common.Address
}

// convertArgs converts args passed from JS to the Go types expected by the ABI inputs.
// It handles address types which are the common cases for ERC20/721 transfers.
func convertArgs(contractABI *abi.ABI, method string, args []any) ([]any, error) {
	var (
		abiMethod    abi.Method
		methodExists bool
	)

	if method == "constructor" {
		if contractABI.Constructor.Inputs == nil {
			// Nothing to convert
			return nil, nil
		}

		abiMethod = contractABI.Constructor
		methodExists = true
	} else {
		abiMethod, methodExists = contractABI.Methods[method]
	}

	if !methodExists {
		return nil, fmt.Errorf("%w: %s", errMethodNotFound, method)
	}

	if len(args) != len(abiMethod.Inputs) {
		return nil, fmt.Errorf("%w: got %d, want %d", errInvalidArgCount, len(args), len(abiMethod.Inputs))
	}

	converted := make([]any, len(args))

	for argIndex, input := range abiMethod.Inputs {
		value, err := convertArg(args[argIndex], input)
		if err != nil {
			return nil, fmt.Errorf("arg %d (%s): %w", argIndex, input.Name, err)
		}

		converted[argIndex] = value
	}

	return converted, nil
}

// convertArg converts an argument passed from JS to the Go type expected by the ABI input.
func convertArg(arg any, input abi.Argument) (any, error) {
	return convertValue(arg, input.Type)
}

// convertValue converts a JS-supplied argument into the concrete Go type the ABI expects.
// The output types mirror abi.Type.GetType() to satisfy go-ethereum's packer.
func convertValue(arg any, typ abi.Type) (any, error) {
	switch typ.T {
	case abi.AddressTy:
		return convertAddress(arg)

	case abi.UintTy, abi.IntTy:
		num, err := convertNumber(arg)
		if err != nil {
			return nil, err
		}
		// Convert to native type based on ABI type size.
		// go-ethereum's ABI packer expects native Go types for fixed-size integers.
		return convertBigIntToNative(num, typ)

	case abi.BytesTy:
		return convertBytes(arg)

	case abi.FixedBytesTy:
		bytesVal, err := convertBytes(arg)
		if err != nil {
			return nil, err
		}

		if len(bytesVal) != typ.Size {
			return nil, fmt.Errorf("%w: expected %d bytes, got %d", errInvalidFixedByteArraySize, typ.Size, len(bytesVal))
		}

		arr := reflect.New(typ.GetType()).Elem()
		reflect.Copy(arr, reflect.ValueOf(bytesVal))

		return arr.Interface(), nil

	case abi.SliceTy, abi.ArrayTy:
		return convertSequence(arg, typ)

	case abi.TupleTy:
		if reflect.TypeOf(arg) == typ.GetType() {
			return arg, nil
		}

		return convertTuple(arg, typ)
	}

	return arg, nil
}

// convertSequence handles both slices and fixed-size arrays.
// Arrays from JS come as []any. Reflection is still needed to create
// properly typed output slices for go-ethereum's ABI packer.
func convertSequence(arg any, typ abi.Type) (any, error) {
	items, ok := arg.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: got %T", errInvalidArrayType, arg)
	}

	isFixedArray := typ.T == abi.ArrayTy
	if isFixedArray && len(items) != typ.Size {
		return nil, fmt.Errorf("%w: expected %d, got %d", errInvalidArrayLength, typ.Size, len(items))
	}

	// Reflection needed: ABI packer expects typed slices (e.g. []common.Address, []*big.Int)
	elemType := typ.Elem.GetType()

	var result reflect.Value

	if isFixedArray {
		result = reflect.New(reflect.ArrayOf(typ.Size, elemType)).Elem()
	} else {
		result = reflect.MakeSlice(reflect.SliceOf(elemType), len(items), len(items))
	}

	for itemIndex, item := range items {
		converted, err := convertValue(item, *typ.Elem)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", itemIndex, err)
		}

		result.Index(itemIndex).Set(reflect.ValueOf(converted))
	}

	return result.Interface(), nil
}

// convertTuple converts a JS array into a Go struct matching the ABI tuple type.
// Tuples in Solidity (structs) are passed from JS as arrays where each element
// corresponds to a struct field in order.
func convertTuple(arg any, typ abi.Type) (any, error) {
	items, ok := arg.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s, got %T", errInvalidTupleType, typ.String(), arg)
	}

	if len(items) != len(typ.TupleElems) {
		return nil, fmt.Errorf("%w: expected %d fields, got %d", errInvalidTupleType, len(typ.TupleElems), len(items))
	}

	// Create a new instance of the tuple struct type
	result := reflect.New(typ.GetType()).Elem()

	for fieldIndex, elemType := range typ.TupleElems {
		converted, err := convertValue(items[fieldIndex], *elemType)
		if err != nil {
			return nil, fmt.Errorf("field %d (%s): %w", fieldIndex, typ.TupleRawNames[fieldIndex], err)
		}

		result.Field(fieldIndex).Set(reflect.ValueOf(converted))
	}

	return result.Interface(), nil
}

// Addresses passed from JS are strings, so we need to convert them to common.Address.
// Returns an error if the argument is not a string.
func convertAddress(arg any) (common.Address, error) {
	switch v := arg.(type) {
	case string:
		return parseHexAddress(v)
	default:
		return common.Address{}, fmt.Errorf("%w: got %T", errInvalidAddressType, arg)
	}
}

// Numbers passed from JS are int64, we need to convert them to *big.Int.
// Returns an error if the argument is not a int64.
func convertNumber(arg any) (*big.Int, error) {
	switch value := arg.(type) {
	case int:
		return big.NewInt(int64(value)), nil
	case int64:
		return big.NewInt(value), nil
	case uint64:
		return new(big.Int).SetUint64(value), nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, fmt.Errorf("%w: got %v", errInvalidNumberType, value)
		}

		if value > float64(maxSafeInt) || value < float64(minSafeInt) || value != math.Trunc(value) {
			return nil, fmt.Errorf("%w: number out of safe integer range", errInvalidNumberType)
		}

		return big.NewInt(int64(value)), nil
	case *big.Int:
		return value, nil
	case big.Int:
		return &value, nil
	case string:
		clean := strings.TrimSpace(value)
		if clean == "" {
			return nil, fmt.Errorf("%w: empty string", errInvalidNumberType)
		}

		base := 10
		if strings.HasPrefix(clean, "0x") || strings.HasPrefix(clean, "0X") {
			base = 16
			clean = clean[2:]
		}

		num, ok := new(big.Int).SetString(clean, base)
		if !ok {
			return nil, fmt.Errorf("%w: %q", errInvalidNumberType, value)
		}

		return num, nil
	default:
		return nil, fmt.Errorf("%w: got %T", errInvalidNumberType, arg)
	}
}

// convertBigIntToNative converts a *big.Int to the native Go type expected by the ABI packer.
// Uses go-ethereum's typ.GetType() to determine the expected type and reflect for overflow checking.
func convertBigIntToNative(num *big.Int, typ abi.Type) (any, error) {
	expectedType := typ.GetType()

	// For *big.Int types (uint256, int256), return as-is
	if expectedType == reflect.TypeFor[*big.Int]() {
		return num, nil
	}

	// Create a value of the expected type
	val := reflect.New(expectedType).Elem()

	//nolint:exhaustive // Only integer types are relevant for ABI numeric conversion
	switch val.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if !num.IsUint64() || val.OverflowUint(num.Uint64()) {
			return nil, fmt.Errorf("%w: value %s exceeds %s", errIntegerOverflow, num.String(), expectedType)
		}

		val.SetUint(num.Uint64())

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if !num.IsInt64() || val.OverflowInt(num.Int64()) {
			return nil, fmt.Errorf("%w: value %s exceeds %s", errIntegerOverflow, num.String(), expectedType)
		}

		val.SetInt(num.Int64())

	default:
		return num, nil
	}

	return val.Interface(), nil
}

// Bytes from JS come as hex strings (e.g. "0xabcd").
func convertBytes(arg any) ([]byte, error) {
	switch v := arg.(type) {
	case []byte:
		return v, nil
	case string:
		return decodeHexString(v)
	default:
		return nil, fmt.Errorf("%w: got %T", errInvalidBytesType, arg)
	}
}

func decodeHexString(input string) ([]byte, error) {
	clean := strings.TrimPrefix(input, "0x")
	if len(clean)%2 != 0 {
		clean = "0" + clean
	}

	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	return decoded, nil
}

// TxnOpts contains transaction options.
type TxnOpts struct {
	Value      uint64        `js:"value"`
	GasPrice   uint64        `js:"gasPrice"`
	GasLimit   uint64        `js:"gasLimit"`
	Nonce      uint64        `js:"nonce"`
	AccessList []AccessTuple `js:"accessList"`
}

// Call executes a read-only call on the contract.
func (c *Contract) Call(method string, args ...any) (map[string]any, error) {
	if c == nil || c.abi == nil || c.client == nil {
		return nil, errContractNotInitialized
	}

	converted, err := convertArgs(c.abi, method, args)
	if err != nil {
		return nil, err
	}

	input, err := c.abi.Pack(method, converted...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack call data: %w", err)
	}

	msg := ethereum.CallMsg{
		To:   &c.addr,
		Data: input,
	}

	startTime := time.Now()
	output, err := c.client.client.CallContract(c.client.getBaseContext(), msg, nil)
	c.client.reportCallMetrics("eth_call", time.Since(startTime))

	if err != nil {
		c.client.recordError(err, "eth_call")

		return nil, fmt.Errorf("contract call failed: %w", err)
	}

	// Unpack the result.
	abiMethod, exists := c.abi.Methods[method]
	if !exists {
		return nil, fmt.Errorf("%w: %s", errMethodNotFound, method)
	}

	results, err := abiMethod.Outputs.Unpack(output)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack result: %w", err)
	}

	// Build result map.
	result := make(map[string]any)

	for outputIndex, output := range abiMethod.Outputs {
		name := output.Name
		if name == "" {
			name = strconv.Itoa(outputIndex)
		}

		if outputIndex < len(results) {
			result[name] = results[outputIndex]
		}
	}

	return result, nil
}

// EncodeABI encodes a contract method call into bytes-encoded calldata.
func (c *Contract) EncodeABI(method string, args ...any) ([]byte, error) {
	if c == nil || c.abi == nil {
		return nil, errContractNotInitialized
	}

	converted, err := convertArgs(c.abi, method, args)
	if err != nil {
		return nil, err
	}

	input, err := c.abi.Pack(method, converted...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode args: %w", err)
	}

	return input, nil
}

// Txn executes a transaction on the contract and returns the transaction hash.
func (c *Contract) Txn(method string, opts TxnOpts, args ...any) (string, error) {
	if c == nil || c.abi == nil || c.client == nil {
		return "", errContractNotInitialized
	}

	input, err := c.EncodeABI(method, args...)
	if err != nil {
		return "", fmt.Errorf("failed to encode ABI: %w", err)
	}

	value, err := safeInt64FromUint64(opts.Value)
	if err != nil {
		return "", err
	}

	// Build transaction request.
	transaction := Transaction{
		To:         c.addr.Hex(),
		Input:      input,
		GasPrice:   opts.GasPrice,
		Gas:        opts.GasLimit,
		Value:      value,
		Nonce:      opts.Nonce,
		AccessList: opts.AccessList,
	}

	return c.client.SendRawTransaction(transaction)
}

// TxnSync encodes a contract method call and sends it via the client's
// synchronous transaction RPC, returning the mined receipt.
// This uses the same underlying path as Client.SendTransactionSync,
// which records request duration and time-to-mine metrics.
func (c *Contract) TxnSync(method string, opts TxnOpts, args ...any) (*Receipt, error) {
	if c == nil || c.abi == nil || c.client == nil {
		return nil, errContractNotInitialized
	}

	input, err := c.EncodeABI(method, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ABI: %w", err)
	}

	value, err := safeInt64FromUint64(opts.Value)
	if err != nil {
		return nil, err
	}

	// Build transaction request; gas is estimated inside SendTransactionSync path.
	transaction := Transaction{
		To:         c.addr.Hex(),
		Input:      input,
		GasPrice:   opts.GasPrice,
		Gas:        opts.GasLimit,
		Value:      value,
		Nonce:      opts.Nonce,
		AccessList: opts.AccessList,
	}

	// Synchronously send and wait for mined receipt.
	return c.client.SendTransactionSync(transaction)
}

// TxnAndWaitReceipt encodes a contract method call, sends it via eth_sendRawTransaction,
// and polls for the receipt. This uses the same underlying path as Client.SendTransactionAndWaitReceipt,
// which is useful for nodes that don't support eth_sendRawTransactionSync.
func (c *Contract) TxnAndWaitReceipt(method string, opts TxnOpts, args ...any) (*Receipt, error) {
	if c == nil || c.abi == nil || c.client == nil {
		return nil, errContractNotInitialized
	}

	input, err := c.EncodeABI(method, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ABI: %w", err)
	}

	value, err := safeInt64FromUint64(opts.Value)
	if err != nil {
		return nil, err
	}

	// Build transaction request; gas is estimated inside SendTransactionAndWaitReceipt path.
	transaction := Transaction{
		To:         c.addr.Hex(),
		Input:      input,
		GasPrice:   opts.GasPrice,
		Gas:        opts.GasLimit,
		Value:      value,
		Nonce:      opts.Nonce,
		AccessList: opts.AccessList,
	}

	// Send and poll for receipt.
	return c.client.SendTransactionAndWaitReceipt(transaction)
}

// ParseReceiptEvents decodes logs in the receipt using the contract ABI.
// It returns a slice of parsed events with JS-friendly argument values.
func (c *Contract) ParseReceiptEvents(receipt *Receipt) ([]*ParsedEvent, error) {
	if c == nil || c.abi == nil {
		return nil, errContractNotInitialized
	}

	if receipt == nil {
		return nil, errReceiptRequired
	}

	if len(receipt.Logs) == 0 {
		return []*ParsedEvent{}, nil
	}

	eventsByID := buildEventIndex(c.abi)
	parsed := make([]*ParsedEvent, 0, len(receipt.Logs))

	for logIndex, logEntry := range receipt.Logs {
		event, ok := c.matchLogToEvent(logEntry, eventsByID)
		if !ok {
			continue
		}

		parsedEvent, err := c.parseLogEntry(logIndex, logEntry, event)
		if err != nil {
			return nil, err
		}

		parsed = append(parsed, parsedEvent)
	}

	return parsed, nil
}

// buildEventIndex creates a lookup map of event ID to event definition.
func buildEventIndex(contractABI *abi.ABI) map[common.Hash]abi.Event {
	eventsByID := make(map[common.Hash]abi.Event, len(contractABI.Events))

	for _, event := range contractABI.Events {
		if !event.Anonymous {
			eventsByID[event.ID] = event
		}
	}

	return eventsByID
}

// matchLogToEvent checks if a log matches a known event in the contract.
// Returns the matching event and true if found, or empty event and false otherwise.
func (c *Contract) matchLogToEvent(logEntry *Log, eventsByID map[common.Hash]abi.Event) (abi.Event, bool) {
	if logEntry == nil || len(logEntry.Topics) == 0 {
		return abi.Event{}, false
	}

	if c.addr != (common.Address{}) && common.HexToAddress(logEntry.Address) != c.addr {
		return abi.Event{}, false
	}

	topic0 := common.HexToHash(logEntry.Topics[0])
	event, ok := eventsByID[topic0]

	return event, ok
}

// parseLogEntry decodes a single log entry into a ParsedEvent.
func (c *Contract) parseLogEntry(logIndex int, logEntry *Log, event abi.Event) (*ParsedEvent, error) {
	args, err := decodeEventData(logIndex, logEntry, event)
	if err != nil {
		return nil, err
	}

	if err := parseIndexedArgs(logIndex, logEntry, event, args); err != nil {
		return nil, err
	}

	normalized := make(map[string]any, len(args))

	for key, value := range args {
		normalized[key] = normalizeValue(value)
	}

	return &ParsedEvent{
		Name:        event.Name,
		Signature:   event.Sig,
		Address:     logEntry.Address,
		BlockNumber: logEntry.BlockNumber,
		TxHash:      logEntry.TxHash,
		TxIndex:     logEntry.TxIndex,
		BlockHash:   logEntry.BlockHash,
		LogIndex:    logEntry.Index,
		Removed:     logEntry.Removed,
		Topics:      logEntry.Topics,
		Data:        logEntry.Data,
		Args:        normalized,
	}, nil
}

// decodeEventData unpacks non-indexed event arguments from the log data.
func decodeEventData(logIndex int, logEntry *Log, event abi.Event) (map[string]any, error) {
	dataBytes, err := decodeHexString(logEntry.Data)
	if err != nil {
		return nil, fmt.Errorf("log %d (%s): invalid data: %w", logIndex, event.Name, err)
	}

	args := make(map[string]any)
	if err := event.Inputs.NonIndexed().UnpackIntoMap(args, dataBytes); err != nil {
		return nil, fmt.Errorf("log %d (%s): failed to unpack data: %w", logIndex, event.Name, err)
	}

	return args, nil
}

// parseIndexedArgs decodes indexed event arguments from log topics.
func parseIndexedArgs(logIndex int, logEntry *Log, event abi.Event, args map[string]any) error {
	indexed := indexedArguments(event.Inputs)
	if len(indexed) == 0 {
		return nil
	}

	if len(logEntry.Topics) < 1 {
		return fmt.Errorf("log %d (%s): %w", logIndex, event.Name, errMissingEventSignature)
	}

	topics := make([]common.Hash, 0, len(logEntry.Topics)-1)

	for _, topic := range logEntry.Topics[1:] {
		topics = append(topics, common.HexToHash(topic))
	}

	if err := abi.ParseTopicsIntoMap(args, indexed, topics); err != nil {
		return fmt.Errorf("log %d (%s): failed to parse topics: %w", logIndex, event.Name, err)
	}

	return nil
}

func indexedArguments(arguments abi.Arguments) abi.Arguments {
	var indexed []abi.Argument

	for _, arg := range arguments {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}

	return indexed
}
