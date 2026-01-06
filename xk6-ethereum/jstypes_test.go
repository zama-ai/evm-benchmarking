package ethereum

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
)

func TestNewLog(t *testing.T) {
	log := &types.Log{
		Address:     common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		Topics:      []common.Hash{common.HexToHash("0x01"), common.HexToHash("0x02")},
		Data:        []byte{0xde, 0xad, 0xbe, 0xef},
		BlockNumber: 7,
		TxHash:      common.HexToHash("0x1234"),
		TxIndex:     2,
		BlockHash:   common.HexToHash("0x5678"),
		Index:       3,
		Removed:     true,
	}

	wrapped := NewLog(log)
	require.Equal(t, log.Address.Hex(), wrapped.Address)
	require.Equal(t, []string{log.Topics[0].Hex(), log.Topics[1].Hex()}, wrapped.Topics)
	require.Equal(t, "deadbeef", wrapped.Data)
	require.Equal(t, log.BlockNumber, wrapped.BlockNumber)
	require.Equal(t, log.TxHash.Hex(), wrapped.TxHash)
	require.Equal(t, log.TxIndex, wrapped.TxIndex)
	require.Equal(t, log.BlockHash.Hex(), wrapped.BlockHash)
	require.Equal(t, log.Index, wrapped.Index)
	require.Equal(t, log.Removed, wrapped.Removed)
}

func TestNewReceipt(t *testing.T) {
	receipt := &types.Receipt{
		Type:              types.DynamicFeeTxType,
		PostState:         []byte{0x01, 0x02},
		Status:            1,
		CumulativeGasUsed: 21000,
		Bloom:             types.Bloom{0x01},
		Logs: []*types.Log{
			{Address: common.HexToAddress("0x000000000000000000000000000000000000dEaD")},
		},
		TxHash:            common.HexToHash("0x1234"),
		ContractAddress:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		GasUsed:           21000,
		BlockHash:         common.HexToHash("0x5678"),
		TransactionIndex:  1,
		EffectiveGasPrice: big.NewInt(42),
		BlobGasUsed:       100,
		BlobGasPrice:      big.NewInt(7),
		BlockNumber:       big.NewInt(9),
	}

	wrapped := NewReceipt(receipt)
	require.Equal(t, receipt.Type, wrapped.Type)
	require.Equal(t, receipt.PostState, wrapped.PostState)
	require.Equal(t, receipt.Status, wrapped.Status)
	require.Equal(t, receipt.CumulativeGasUsed, wrapped.CumulativeGasUsed)
	require.Equal(t, receipt.Bloom.Bytes(), wrapped.Bloom)
	require.Len(t, wrapped.Logs, 1)
	require.Equal(t, receipt.TxHash.Hex(), wrapped.TxHash)
	require.Equal(t, receipt.ContractAddress.Hex(), wrapped.ContractAddress)
	require.Equal(t, receipt.GasUsed, wrapped.GasUsed)
	require.Equal(t, receipt.EffectiveGasPrice.Uint64(), wrapped.EffectiveGasPrice)
	require.Equal(t, receipt.BlobGasUsed, wrapped.BlobGasUsed)
	require.Equal(t, receipt.BlobGasPrice.Uint64(), wrapped.BlobGasPrice)
	require.Equal(t, receipt.BlockHash.Hex(), wrapped.BlockHash)
	require.Equal(t, receipt.BlockNumber.Uint64(), wrapped.BlockNumber)
	require.Equal(t, receipt.TransactionIndex, wrapped.TransactionIndex)
}

func TestNewBlockAndBlockTransaction(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	signer := types.LatestSignerForChainID(big.NewInt(1))

	legacyTx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &to,
		Value:    big.NewInt(5),
		Gas:      21000,
		GasPrice: big.NewInt(1000),
	})
	legacyTx, err = types.SignTx(legacyTx, signer, privateKey)
	require.NoError(t, err)

	dynamicTx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     2,
		To:        &to,
		Value:     big.NewInt(7),
		Gas:       25000,
		GasFeeCap: big.NewInt(2000),
		GasTipCap: big.NewInt(100),
	})
	dynamicTx, err = types.SignTx(dynamicTx, signer, privateKey)
	require.NoError(t, err)

	header := &types.Header{
		Number:     big.NewInt(3),
		Time:       12345,
		GasLimit:   1000000,
		Difficulty: big.NewInt(1),
		BaseFee:    big.NewInt(100),
		UncleHash:  types.EmptyUncleHash,
	}

	body := &types.Body{
		Transactions: []*types.Transaction{legacyTx, dynamicTx},
	}

	block := types.NewBlock(header, body, nil, trie.NewListHasher())
	wrapped := NewBlock(block)

	require.Equal(t, header.Number.Uint64(), wrapped.Number)
	require.Equal(t, header.ParentHash.Hex(), wrapped.ParentHash)
	require.Equal(t, header.UncleHash.Hex(), wrapped.Sha3Uncles)
	require.Equal(t, header.Root.Hex(), wrapped.StateRoot)
	require.Equal(t, header.Coinbase.Hex(), wrapped.Miner)
	require.Equal(t, header.Difficulty.String(), wrapped.Difficulty)
	require.Equal(t, header.GasLimit, wrapped.GasLimit)
	require.Equal(t, header.Time, wrapped.Timestamp)
	require.Equal(t, header.Nonce.Uint64(), wrapped.Nonce)
	require.Equal(t, header.BaseFee.String(), wrapped.BaseFeePerGas)
	require.Len(t, wrapped.Transactions, 2)

	legacyWrapped := NewBlockTransaction(legacyTx)
	require.Equal(t, uint8(types.LegacyTxType), legacyWrapped.Type)
	require.NotEmpty(t, legacyWrapped.From)
	require.Equal(t, legacyTx.GasPrice().String(), legacyWrapped.GasPrice)
	require.Equal(t, legacyTx.Value().String(), legacyWrapped.Value)

	dynamicWrapped := NewBlockTransaction(dynamicTx)
	require.Equal(t, uint8(types.DynamicFeeTxType), dynamicWrapped.Type)
	require.NotEmpty(t, dynamicWrapped.From)
	require.Equal(t, dynamicTx.GasFeeCap().String(), dynamicWrapped.MaxFeePerGas)
	require.Equal(t, dynamicTx.GasTipCap().String(), dynamicWrapped.MaxPriorityFeePerGas)
}

func TestBigIntToHex(t *testing.T) {
	require.Equal(t, "0x0", bigIntToHex(nil))
	require.Equal(t, "0x2a", bigIntToHex(big.NewInt(42)))
}
