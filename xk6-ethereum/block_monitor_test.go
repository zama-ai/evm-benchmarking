package ethereum

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
)

var (
	errTestBlockNumberFailure = errors.New("block number check failed")
	errTestSubscriptionClosed = errors.New("subscription closed")
)

func TestBlockMonitorHandleBlockHeaderEmitsMetricsAfterFirstHeader(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	toAddress := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	signer := types.LatestSignerForChainID(big.NewInt(1))

	tx1 := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		To:       &toAddress,
		Value:    big.NewInt(1),
		Gas:      21000,
		GasPrice: big.NewInt(1000),
	})
	tx1, err = types.SignTx(tx1, signer, privateKey)
	require.NoError(t, err)

	tx2 := types.NewTx(&types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    2,
		To:       &toAddress,
		Value:    big.NewInt(2),
		Gas:      25000,
		GasPrice: big.NewInt(1),
	})
	tx2, err = types.SignTx(tx2, signer, privateKey)
	require.NoError(t, err)

	header := &types.Header{
		Number:   big.NewInt(2),
		Time:     1001,
		GasLimit: 1000000,
	}
	body := &types.Body{Transactions: []*types.Transaction{tx1, tx2}}
	block := types.NewBlock(header, body, nil, trie.NewListHasher())

	client := &Client{}

	var (
		fetchCalls int
		emitCalls  int
		gotUserTxs int
		gotBlockMs float64
		gotTime    time.Time
	)

	monitor := &BlockMonitor{
		client:    client,
		batchSize: 2,
		fetchBlock: func(_ context.Context, _ common.Hash) (*types.Block, error) {
			fetchCalls++

			return block, nil
		},
		emitMetrics: func(_ *types.Block, userTxCount int, blockTimeMs float64, blockTimestamp time.Time) {
			emitCalls++
			gotUserTxs = userTxCount
			gotBlockMs = blockTimeMs
			gotTime = blockTimestamp
		},
	}

	firstHeader := &types.Header{Number: big.NewInt(1), Time: 1000}
	monitor.handleBlockHeader(firstHeader)
	require.Equal(t, 0, fetchCalls, "first header should only prime lastBlockTime")
	require.Equal(t, 0, emitCalls)

	secondHeader := &types.Header{Number: big.NewInt(2), Time: 1001}
	monitor.handleBlockHeader(secondHeader)

	require.Equal(t, 1, fetchCalls)
	require.Equal(t, 1, emitCalls)
	require.Equal(t, 2, gotUserTxs)
	require.InDelta(t, 1000.0, gotBlockMs, 0.01)
	require.Equal(t, int64(1001), gotTime.Unix())
	require.Equal(t, int64(2), int64(gotTime.Nanosecond()))
}

func TestBlockMonitorCheckInactivityReconnectsWhenHeadAdvanced(t *testing.T) {
	now := time.Now()

	var reconnects int

	monitor := &BlockMonitor{
		client:            &Client{},
		inactivityTimeout: 10 * time.Second,
		lastHeaderTime:    now.Add(-11 * time.Second),
		lastLivenessCheck: now.Add(-11 * time.Second),
		lastHeaderNumber:  100,
		blockNumberFn: func(context.Context) (uint64, error) {
			return 105, nil
		},
		reconnectFn: func() {
			reconnects++
		},
	}

	monitor.checkInactivity()

	require.Equal(t, 1, reconnects)
}

func TestBlockMonitorCheckInactivityDoesNotReconnectWhenHeadStalled(t *testing.T) {
	now := time.Now()

	var reconnects int

	monitor := &BlockMonitor{
		client:            &Client{},
		inactivityTimeout: 10 * time.Second,
		lastHeaderTime:    now.Add(-11 * time.Second),
		lastLivenessCheck: now.Add(-11 * time.Second),
		lastHeaderNumber:  100,
		blockNumberFn: func(context.Context) (uint64, error) {
			return 100, nil
		},
		reconnectFn: func() {
			reconnects++
		},
	}

	monitor.checkInactivity()

	require.Equal(t, 0, reconnects)
}

func TestBlockMonitorCheckInactivityReconnectsOnBlockNumberError(t *testing.T) {
	now := time.Now()

	var reconnects int

	monitor := &BlockMonitor{
		client:            &Client{},
		inactivityTimeout: 10 * time.Second,
		lastHeaderTime:    now.Add(-11 * time.Second),
		lastLivenessCheck: now.Add(-11 * time.Second),
		lastHeaderNumber:  100,
		blockNumberFn: func(context.Context) (uint64, error) {
			return 0, errTestBlockNumberFailure
		},
		reconnectFn: func() {
			reconnects++
		},
	}

	monitor.checkInactivity()

	require.Equal(t, 1, reconnects)
}

func TestBlockMonitorHandleSubErrorReconnects(t *testing.T) {
	var reconnects int

	monitor := &BlockMonitor{
		client: &Client{},
		reconnectFn: func() {
			reconnects++
		},
	}

	monitor.handleSubError(errTestSubscriptionClosed)

	require.Equal(t, 1, reconnects)
}
