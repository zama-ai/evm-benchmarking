package ethereum

import (
	"encoding/hex"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Package ethereum provides wrapper types for go-ethereum types that expose
// proper js struct tags for k6's Go-to-JavaScript bridge.
//
// Problem: go-ethereum types use `json` struct tags (e.g., `json:"contractAddress"`),
// but k6's sobek runtime uses `js` tags. Without `js` tags, field names get converted
// to snake_case (e.g., ContractAddress → contract_address), breaking the expected
// camelCase JavaScript API.
//
// Solution: Define wrapper types that mirror go-ethereum types but with `js` tags,
// and convert before returning to JavaScript.

// Receipt wraps go-ethereum's types.Receipt with proper js tags for k6.
// Field names match the json serialization from go-ethereum for API consistency.
type Receipt struct {
	Type              uint8  `js:"type"`
	PostState         []byte `js:"root"`
	Status            uint64 `js:"status"`
	CumulativeGasUsed uint64 `js:"cumulativeGasUsed"`
	Bloom             []byte `js:"logsBloom"`
	Logs              []*Log `js:"logs"`
	TxHash            string `js:"transactionHash"`
	ContractAddress   string `js:"contractAddress"`
	GasUsed           uint64 `js:"gasUsed"`
	EffectiveGasPrice uint64 `js:"effectiveGasPrice"`
	BlobGasUsed       uint64 `js:"blobGasUsed,omitempty"`
	BlobGasPrice      uint64 `js:"blobGasPrice,omitempty"`
	BlockHash         string `js:"blockHash"`
	BlockNumber       uint64 `js:"blockNumber"`
	TransactionIndex  uint   `js:"transactionIndex"`
}

// Log wraps go-ethereum's types.Log with proper js tags for k6.
type Log struct {
	Address     string   `js:"address"`
	Topics      []string `js:"topics"`
	Data        string   `js:"data"`
	BlockNumber uint64   `js:"blockNumber"`
	TxHash      string   `js:"transactionHash"`
	TxIndex     uint     `js:"transactionIndex"`
	BlockHash   string   `js:"blockHash"`
	Index       uint     `js:"logIndex"`
	Removed     bool     `js:"removed"`
}

// ParsedEvent represents a decoded EVM event with normalized argument values.
type ParsedEvent struct {
	Name        string         `js:"name"`
	Signature   string         `js:"signature"`
	Address     string         `js:"address"`
	BlockNumber uint64         `js:"blockNumber"`
	TxHash      string         `js:"transactionHash"`
	TxIndex     uint           `js:"transactionIndex"`
	BlockHash   string         `js:"blockHash"`
	LogIndex    uint           `js:"logIndex"`
	Removed     bool           `js:"removed"`
	Topics      []string       `js:"topics"`
	Data        string         `js:"data"`
	Args        map[string]any `js:"args"`
}

// Block wraps go-ethereum's types.Block with proper js tags for k6.
// go-ethereum's Block uses methods instead of exported fields, so we extract
// values into a flat struct for JavaScript consumption.
type Block struct {
	Number           uint64              `js:"number"`
	Hash             string              `js:"hash"`
	ParentHash       string              `js:"parentHash"`
	Sha3Uncles       string              `js:"sha3Uncles"`
	TransactionsRoot string              `js:"transactionsRoot"`
	StateRoot        string              `js:"stateRoot"`
	ReceiptsRoot     string              `js:"receiptsRoot"`
	Miner            string              `js:"miner"`
	Difficulty       string              `js:"difficulty"`
	ExtraData        string              `js:"extraData"`
	GasLimit         uint64              `js:"gasLimit"`
	GasUsed          uint64              `js:"gasUsed"`
	Timestamp        uint64              `js:"timestamp"`
	MixHash          string              `js:"mixHash"`
	Nonce            uint64              `js:"nonce"`
	BaseFeePerGas    string              `js:"baseFeePerGas,omitempty"`
	Transactions     []*BlockTransaction `js:"transactions"`
}

// BlockTransaction represents a transaction within a block.
type BlockTransaction struct {
	Type                 uint8  `js:"type"`
	Hash                 string `js:"hash"`
	From                 string `js:"from,omitempty"`
	To                   string `js:"to,omitempty"`
	Input                string `js:"input"`
	Gas                  uint64 `js:"gas"`
	GasPrice             string `js:"gasPrice,omitempty"`
	MaxFeePerGas         string `js:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas string `js:"maxPriorityFeePerGas,omitempty"`
	Value                string `js:"value"`
	Nonce                uint64 `js:"nonce"`
	ChainID              uint64 `js:"chainId,omitempty"`
	V                    string `js:"v"`
	R                    string `js:"r"`
	S                    string `js:"s"`
}

// NewReceipt converts a go-ethereum Receipt to our wrapped Receipt type.
func NewReceipt(inputReceipt *types.Receipt) *Receipt {
	if inputReceipt == nil {
		return nil
	}

	logs := make([]*Log, len(inputReceipt.Logs))
	for i, l := range inputReceipt.Logs {
		logs[i] = NewLog(l)
	}

	receipt := &Receipt{
		Type:              inputReceipt.Type,
		PostState:         inputReceipt.PostState,
		Status:            inputReceipt.Status,
		CumulativeGasUsed: inputReceipt.CumulativeGasUsed,
		Bloom:             inputReceipt.Bloom.Bytes(),
		Logs:              logs,
		TxHash:            inputReceipt.TxHash.Hex(),
		ContractAddress:   inputReceipt.ContractAddress.Hex(),
		GasUsed:           inputReceipt.GasUsed,
		BlobGasUsed:       inputReceipt.BlobGasUsed,
		BlockHash:         inputReceipt.BlockHash.Hex(),
		TransactionIndex:  inputReceipt.TransactionIndex,
	}

	if inputReceipt.EffectiveGasPrice != nil {
		receipt.EffectiveGasPrice = inputReceipt.EffectiveGasPrice.Uint64()
	}

	if inputReceipt.BlobGasPrice != nil {
		receipt.BlobGasPrice = inputReceipt.BlobGasPrice.Uint64()
	}

	if inputReceipt.BlockNumber != nil {
		receipt.BlockNumber = inputReceipt.BlockNumber.Uint64()
	}

	return receipt
}

// NewLog converts a go-ethereum Log to our wrapped Log type.
func NewLog(inputLog *types.Log) *Log {
	if inputLog == nil {
		return nil
	}

	topics := make([]string, len(inputLog.Topics))
	for i, t := range inputLog.Topics {
		topics[i] = t.Hex()
	}

	return &Log{
		Address:     inputLog.Address.Hex(),
		Topics:      topics,
		Data:        common.Bytes2Hex(inputLog.Data),
		BlockNumber: inputLog.BlockNumber,
		TxHash:      inputLog.TxHash.Hex(),
		TxIndex:     inputLog.TxIndex,
		BlockHash:   inputLog.BlockHash.Hex(),
		Index:       inputLog.Index,
		Removed:     inputLog.Removed,
	}
}

// NewBlock converts a go-ethereum Block to our wrapped Block type.
func NewBlock(inputBlock *types.Block) *Block {
	if inputBlock == nil {
		return nil
	}

	txs := inputBlock.Transactions()
	transactions := make([]*BlockTransaction, len(txs))

	for i, tx := range txs {
		transactions[i] = NewBlockTransaction(tx)
	}

	block := &Block{
		Number:           inputBlock.NumberU64(),
		Hash:             inputBlock.Hash().Hex(),
		ParentHash:       inputBlock.ParentHash().Hex(),
		Sha3Uncles:       inputBlock.UncleHash().Hex(),
		TransactionsRoot: inputBlock.TxHash().Hex(),
		StateRoot:        inputBlock.Root().Hex(),
		ReceiptsRoot:     inputBlock.ReceiptHash().Hex(),
		Miner:            inputBlock.Coinbase().Hex(),
		Difficulty:       inputBlock.Difficulty().String(),
		ExtraData:        common.Bytes2Hex(inputBlock.Extra()),
		GasLimit:         inputBlock.GasLimit(),
		GasUsed:          inputBlock.GasUsed(),
		Timestamp:        inputBlock.Time(),
		MixHash:          inputBlock.MixDigest().Hex(),
		Nonce:            inputBlock.Nonce(),
		Transactions:     transactions,
	}

	if baseFee := inputBlock.BaseFee(); baseFee != nil {
		block.BaseFeePerGas = baseFee.String()
	}

	return block
}

// NewBlockTransaction converts a go-ethereum Transaction to our wrapped BlockTransaction type.
func NewBlockTransaction(inputTx *types.Transaction) *BlockTransaction { //nolint:cyclop
	if inputTx == nil {
		return nil
	}

	btx := &BlockTransaction{
		Type:  inputTx.Type(),
		Hash:  inputTx.Hash().Hex(),
		Input: common.Bytes2Hex(inputTx.Data()),
		Gas:   inputTx.Gas(),
		Value: inputTx.Value().String(),
		Nonce: inputTx.Nonce(),
	}

	// To address (nil for contract creation)
	if to := inputTx.To(); to != nil {
		btx.To = to.Hex()
	}

	// Chain ID
	if chainID := inputTx.ChainId(); chainID != nil {
		btx.ChainID = chainID.Uint64()
	}

	// Gas pricing - depends on tx type
	if inputTx.Type() == types.DynamicFeeTxType || inputTx.Type() == types.BlobTxType {
		if tip := inputTx.GasTipCap(); tip != nil {
			btx.MaxPriorityFeePerGas = tip.String()
		}

		if fee := inputTx.GasFeeCap(); fee != nil {
			btx.MaxFeePerGas = fee.String()
		}
	} else if gp := inputTx.GasPrice(); gp != nil {
		btx.GasPrice = gp.String()
	}

	// Signature values
	v, r, s := inputTx.RawSignatureValues()
	btx.V = bigIntToHex(v)
	btx.R = bigIntToHex(r)
	btx.S = bigIntToHex(s)

	// Recover sender address (from) using the signer
	// We use LatestSignerForChainID which handles all tx types
	if chainID := inputTx.ChainId(); chainID != nil {
		signer := types.LatestSignerForChainID(chainID)
		if from, err := types.Sender(signer, inputTx); err == nil {
			btx.From = from.Hex()
		}
	}

	return btx
}

// bigIntToHex converts a big.Int to a hex string with 0x prefix.
func bigIntToHex(n *big.Int) string {
	if n == nil {
		return "0x0"
	}

	return "0x" + n.Text(16)
}

// normalizeValue converts Go values to JS-friendly types for the k6 bridge.
func normalizeValue(value any) any {
	if value == nil {
		return nil
	}

	if result, handled := normalizeKnownTypes(value); handled {
		return result
	}

	return normalizeReflect(value)
}

// normalizeKnownTypes handles common Go types that need JS-friendly conversion.
// Returns (result, true) if the type was handled, (nil, false) otherwise.
func normalizeKnownTypes(value any) (any, bool) {
	switch typedVal := value.(type) {
	case common.Address:
		return typedVal.Hex(), true
	case common.Hash:
		return typedVal.Hex(), true
	case *big.Int:
		if typedVal == nil {
			return nil, true
		}

		return typedVal.String(), true
	case big.Int:
		return typedVal.String(), true
	case []byte:
		return "0x" + hex.EncodeToString(typedVal), true
	case map[string]any:
		normalized := make(map[string]any, len(typedVal))

		for key, val := range typedVal {
			normalized[key] = normalizeValue(val)
		}

		return normalized, true
	default:
		return nil, false
	}
}

// normalizeReflect handles types via reflection for the JS bridge.
func normalizeReflect(value any) any {
	reflectVal := reflect.ValueOf(value)
	if !reflectVal.IsValid() {
		return nil
	}

	switch reflectVal.Kind() { //nolint:exhaustive // Only handle types that need conversion.
	case reflect.Ptr:
		return normalizePointer(reflectVal)
	case reflect.Slice, reflect.Array:
		return normalizeSliceOrArray(reflectVal)
	case reflect.Struct:
		return normalizeStruct(reflectVal)
	default:
		return value
	}
}

// normalizePointer dereferences a pointer and normalizes its value.
func normalizePointer(reflectVal reflect.Value) any {
	if reflectVal.IsNil() {
		return nil
	}

	return normalizeValue(reflectVal.Elem().Interface())
}

// normalizeSliceOrArray converts slices and arrays to JS-friendly format.
func normalizeSliceOrArray(reflectVal reflect.Value) any {
	length := reflectVal.Len()

	// Byte arrays/slices become hex strings.
	if reflectVal.Type().Elem().Kind() == reflect.Uint8 {
		bytes := make([]byte, length)

		for idx := range length {
			bytes[idx] = byte(reflectVal.Index(idx).Uint())
		}

		return "0x" + hex.EncodeToString(bytes)
	}

	// Other slices/arrays are recursively normalized.
	out := make([]any, length)

	for idx := range length {
		out[idx] = normalizeValue(reflectVal.Index(idx).Interface())
	}

	return out
}

// normalizeStruct converts exported struct fields to a map.
func normalizeStruct(reflectVal reflect.Value) any {
	out := make(map[string]any)
	reflectType := reflectVal.Type()

	for idx := range reflectVal.NumField() {
		field := reflectType.Field(idx)
		if !field.IsExported() {
			continue
		}

		out[field.Name] = normalizeValue(reflectVal.Field(idx).Interface())
	}

	if len(out) > 0 {
		return out
	}

	return reflectVal.Interface()
}
