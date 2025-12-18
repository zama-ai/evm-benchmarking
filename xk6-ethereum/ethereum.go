// Package ethereum provides an xk6 extension for Ethereum client operations.
package ethereum

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/grafana/sobek"
	"go.k6.io/k6/js/modules"
	"go.k6.io/k6/metrics"
)

// Static errors for ethereum operations.
var (
	errReceiptNotFound      = errors.New("receipt not found")
	errNoCallsProvided      = errors.New("no calls provided for batch")
	errWalletNotInitialized = errors.New("wallet not initialized")
)

// maxTxRetries is the maximum number of retries for transaction submission.
const maxTxRetries = 3

// AccessTuple represents a single entry in an EIP-2930 access list.
type AccessTuple struct {
	Address     string   `js:"address"`
	StorageKeys []string `js:"storageKeys"`
}

// Transaction represents an Ethereum transaction.
type Transaction struct {
	From       string        `js:"from"`
	To         string        `js:"to"`
	Input      []byte        `js:"input"`
	GasPrice   uint64        `js:"gasPrice"`
	GasFeeCap  uint64        `js:"gasFeeCap"`
	GasTipCap  uint64        `js:"gasTipCap"`
	Gas        uint64        `js:"gas"`
	Value      int64         `js:"value"`
	Nonce      uint64        `js:"nonce"`
	AccessList []AccessTuple `js:"accessList"`
}

// Call3 represents a call for Multicall3's aggregate3 function.
type Call3 struct {
	Target       string `js:"target"`
	AllowFailure bool   `js:"allowFailure"`
	Calldata     []byte `js:"calldata"`
}

// Call3Value represents a call with value for Multicall3's aggregate3Value function.
type Call3Value struct {
	Target       string `js:"target"`
	AllowFailure bool   `js:"allowFailure"`
	Value        uint64 `js:"value"`
	Calldata     []byte `js:"calldata"`
}

// Client is the Ethereum JSON-RPC client.
type Client struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
	client     *ethclient.Client
	rpcClient  *rpc.Client
	chainID    *big.Int
	vu         modules.VU
	metrics    ethMetrics
	opts       *options
}

func (c *Client) runtimeTagSet() *metrics.TagSet {
	if c == nil || c.vu == nil {
		return nil
	}

	state := c.vu.State()
	if state == nil || state.Tags == nil {
		return nil
	}

	return state.Tags.GetCurrentValues().Tags
}

func (c *Client) reportCallMetrics(endpoint string, duration time.Duration) {
	rootTS := c.runtimeTagSet()
	if rootTS == nil {
		return
	}

	tags := rootTS.With("endpoint", endpoint)

	timestamp := time.Now()
	metrics.PushIfNotDone(c.vu.Context(), c.vu.State().Samples, metrics.Sample{
		TimeSeries: metrics.TimeSeries{
			Metric: c.metrics.RequestDuration,
			Tags:   tags,
		},
		Value: float64(duration / time.Millisecond),
		Time:  timestamp,
	})
}

// sanitizeTagValue sanitizes an error message for use as an InfluxDB tag value.
// InfluxDB line protocol doesn't allow commas, spaces, or equals signs in tag values
// without escaping, and long messages can cause issues.
func sanitizeTagValue(msg string) string {
	const maxLen = 100

	// Replace problematic characters for InfluxDB line protocol
	replacer := strings.NewReplacer(
		",", "_",
		" ", "_",
		"=", "_",
		"\n", "_",
		"\r", "_",
		"\"", "",
		"'", "",
		"{", "",
		"}", "",
		"[", "",
		"]", "",
	)
	sanitized := replacer.Replace(msg)

	// Truncate if too long
	if len(sanitized) > maxLen {
		sanitized = sanitized[:maxLen]
	}

	return sanitized
}

// recordError emits an error metric with the method name and error message.
func (c *Client) recordError(err error, method string) {
	if err == nil {
		return
	}

	rootTS := c.runtimeTagSet()
	if rootTS == nil {
		return
	}

	tags := rootTS.With("method", method).With("reason", sanitizeTagValue(err.Error()))

	metrics.PushIfNotDone(c.vu.Context(), c.vu.State().Samples, metrics.Sample{
		TimeSeries: metrics.TimeSeries{
			Metric: c.metrics.Errors,
			Tags:   tags,
		},
		Value: 1,
		Time:  time.Now(),
	})
}

// Exports implements the modules.Instance interface.
func (c *Client) Exports() modules.Exports {
	return modules.Exports{}
}

// Call executes a raw JSON-RPC call.
func (c *Client) Call(method string, params ...any) (any, error) {
	var out any

	startTime := time.Now()
	err := c.rpcClient.Call(&out, method, params...)
	c.reportCallMetrics(method, time.Since(startTime))

	if err != nil {
		c.recordError(err, method)
	}

	return out, err //nolint:wrapcheck // Raw RPC call returns unwrapped errors.
}

// GasPrice returns the current gas price.
func (c *Client) GasPrice() (uint64, error) {
	startTime := time.Now()
	gasPrice, err := c.client.SuggestGasPrice(context.Background())
	c.reportCallMetrics("gas_price", time.Since(startTime))

	if err != nil {
		c.recordError(err, "gas_price")

		return 0, fmt.Errorf("failed to get gas price: %w", err)
	}

	return gasPrice.Uint64(), nil
}

// GetBalance returns the balance of the given address.
// blockNumber: use nil for latest, or a specific block number.
func (c *Client) GetBalance(address string, blockNumber *big.Int) (uint64, error) {
	startTime := time.Now()
	balance, err := c.client.BalanceAt(context.Background(), common.HexToAddress(address), blockNumber)
	c.reportCallMetrics("eth_getBalance", time.Since(startTime))

	if err != nil {
		c.recordError(err, "eth_getBalance")

		return 0, fmt.Errorf("failed to get balance: %w", err)
	}

	return balance.Uint64(), nil
}

// BlockNumber returns the current block number.
func (c *Client) BlockNumber() (uint64, error) {
	startTime := time.Now()
	blockNum, err := c.client.BlockNumber(context.Background())
	c.reportCallMetrics("eth_blockNumber", time.Since(startTime))

	if err != nil {
		c.recordError(err, "eth_blockNumber")

		return 0, fmt.Errorf("failed to get block number: %w", err)
	}

	return blockNum, nil
}

// GetBlockByNumber returns the block with the given block number.
// number: use nil for latest block.
func (c *Client) GetBlockByNumber(number *big.Int) (*Block, error) {
	startTime := time.Now()
	block, err := c.client.BlockByNumber(context.Background(), number)
	c.reportCallMetrics("eth_getBlockByNumber", time.Since(startTime))

	if err != nil {
		c.recordError(err, "eth_getBlockByNumber")

		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	return NewBlock(block), nil
}

// GetNonce returns the nonce for the given address.
func (c *Client) GetNonce(address string) (uint64, error) {
	startTime := time.Now()
	nonce, err := c.client.PendingNonceAt(context.Background(), common.HexToAddress(address))
	c.reportCallMetrics("eth_getTransactionCount", time.Since(startTime))

	if err != nil {
		c.recordError(err, "eth_getTransactionCount")

		return 0, fmt.Errorf("failed to get nonce: %w", err)
	}

	return nonce, nil
}

// EstimateGas returns the estimated gas for the given transaction.
func (c *Client) EstimateGas(transaction Transaction) (uint64, error) {
	// Handle contract creation: empty string To means nil address
	var toAddr *common.Address

	if transaction.To != "" {
		addr := common.HexToAddress(transaction.To)
		toAddr = &addr
	}

	msg := ethereum.CallMsg{
		From:       c.address,
		To:         toAddr,
		Value:      big.NewInt(transaction.Value),
		Data:       transaction.Input,
		GasPrice:   big.NewInt(0).SetUint64(transaction.GasPrice),
		AccessList: convertAccessList(transaction.AccessList),
	}

	if transaction.GasFeeCap > 0 {
		msg.GasFeeCap = big.NewInt(0).SetUint64(transaction.GasFeeCap)
	}

	if transaction.GasTipCap > 0 {
		msg.GasTipCap = big.NewInt(0).SetUint64(transaction.GasTipCap)
	}

	startTime := time.Now()
	gas, err := c.client.EstimateGas(context.Background(), msg)
	c.reportCallMetrics("eth_estimateGas", time.Since(startTime))

	if err != nil {
		c.recordError(err, "eth_estimateGas")

		return 0, fmt.Errorf("failed to estimate gas: %w", err)
	}

	return gas, nil
}

// SendTransaction signs and sends a transaction to the network without waiting for the receipt.
// This is similar to SendRawTransaction but uses the same transaction building logic as SendTransactionSync.
func (c *Client) SendTransaction(transaction Transaction) (string, error) {
	// Default nonce from NonceManager if not explicitly provided.
	if transaction.Nonce == 0 {
		nonce, err := globalNonceManager.Acquire(c, c.address)
		if err != nil {
			c.recordError(err, "eth_sendRawTransaction")

			return "", fmt.Errorf("failed to acquire nonce: %w", err)
		}

		transaction.Nonce = nonce
	}

	typedTx, err := c.buildTypedTx(transaction)
	if err != nil {
		c.recordError(err, "eth_sendRawTransaction")

		return "", fmt.Errorf("failed to build transaction: %w", err)
	}

	signer := types.LatestSignerForChainID(c.chainID)

	signedTx, err := types.SignTx(typedTx, signer, c.privateKey)
	if err != nil {
		c.recordError(err, "eth_sendRawTransaction")

		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	startTime := time.Now()
	err = c.client.SendTransaction(context.Background(), signedTx)
	c.reportCallMetrics("eth_sendRawTransaction", time.Since(startTime))

	if err != nil {
		c.recordError(err, "eth_sendRawTransaction")

		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	return signedTx.Hash().Hex(), nil
}

// SendRawTransaction signs and sends transaction to the network.
func (c *Client) SendRawTransaction(transaction Transaction) (string, error) {
	// Default nonce from NonceManager if not explicitly provided.
	if transaction.Nonce == 0 {
		nonce, err := globalNonceManager.Acquire(c, c.address)
		if err != nil {
			c.recordError(err, "eth_sendRawTransaction")

			return "", fmt.Errorf("failed to acquire nonce: %w", err)
		}

		transaction.Nonce = nonce
	}

	txHash, err := c.signAndSendRaw(transaction)
	if err != nil {
		c.recordError(err, "eth_sendRawTransaction")

		return "", err
	}

	return txHash, nil
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
func (c *Client) GetTransactionReceipt(hash string) (*Receipt, error) {
	startTime := time.Now()
	receipt, err := c.client.TransactionReceipt(context.Background(), common.HexToHash(hash))
	c.reportCallMetrics("eth_getTransactionReceipt", time.Since(startTime))

	if err != nil {
		// go-ethereum returns ethereum.NotFound when receipt is not available
		// This is expected during polling, so don't record it as an error
		if errors.Is(err, ethereum.NotFound) {
			return nil, errReceiptNotFound
		}

		c.recordError(err, "eth_getTransactionReceipt")

		return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	return NewReceipt(receipt), nil
}

// WaitForTransactionReceipt waits for the transaction receipt for the given transaction hash.
func (c *Client) WaitForTransactionReceipt(hash string) *sobek.Promise {
	promise, resolve, reject := c.makeHandledPromise()
	startTime := time.Now()

	go func() {
		for {
			receipt, err := c.GetTransactionReceipt(hash)
			if err != nil {
				if !errors.Is(err, errReceiptNotFound) {
					reject(err)

					return
				}
			}

			if receipt != nil {
				// If we are testing vu is nil.
				if c.vu != nil {
					rootTS := c.runtimeTagSet()
					// Report metrics.
					if rootTS != nil {
						metrics.PushIfNotDone(c.vu.Context(), c.vu.State().Samples, metrics.Sample{
							TimeSeries: metrics.TimeSeries{
								Metric: c.metrics.TimeToMine,
								Tags:   rootTS,
							},
							Value: float64(time.Since(startTime) / time.Millisecond),
							Time:  time.Now(),
						})
					}
				}

				resolve(receipt)

				break
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	return promise
}

// SendTransactionSync signs, sends and waits for the transaction receipt synchronously.
func (c *Client) SendTransactionSync(transaction Transaction) (*Receipt, error) {
	return c.sendTransactionSyncWithRetries(transaction, maxTxRetries)
}

// sendTransactionSyncWithRetries is the internal implementation with retry tracking.
func (c *Client) sendTransactionSyncWithRetries(transaction Transaction, retriesLeft int) (*Receipt, error) {
	// Choose nonce if not provided (shared manager).
	if transaction.Nonce == 0 {
		nonce, err := globalNonceManager.Acquire(c, c.address)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire nonce: %w", err)
		}

		transaction.Nonce = nonce
	}

	typedTx, err := c.buildTypedTx(transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction: %w", err)
	}

	signer := types.LatestSignerForChainID(c.chainID)

	signedTx, err := types.SignTx(typedTx, signer, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	startTime := time.Now()

	receipt, err := c.sendTransactionSync(context.Background(), signedTx, nil)
	if err != nil { //nolint:nestif
		if retriesLeft > 0 {
			switch retryAction(err) {
			case RetryWithNonce:
				// Refresh nonce and retry.
				refreshErr := globalNonceManager.Refresh(c, c.address)
				if refreshErr != nil {
					return nil, fmt.Errorf("failed to refresh nonce: %w", refreshErr)
				}

				transaction.Nonce = 0

				return c.sendTransactionSyncWithRetries(transaction, retriesLeft-1)

			case RetryWithGasPrice:
				// Bump gas price by 10% and retry.
				if transaction.GasFeeCap > 0 {
					transaction.GasFeeCap = transaction.GasFeeCap * 110 / 100
					transaction.GasTipCap = transaction.GasTipCap * 110 / 100
				} else {
					transaction.GasPrice = transaction.GasPrice * 110 / 100
				}

				return c.sendTransactionSyncWithRetries(transaction, retriesLeft-1)

			case NoRetry:
			}
		}

		c.reportCallMetrics("eth_sendRawTransactionSync", time.Since(startTime))
		c.recordError(err, "eth_sendRawTransactionSync")

		return nil, fmt.Errorf("failed to send transaction sync: %w", err)
	}

	duration := time.Since(startTime)
	c.reportCallMetrics("eth_sendRawTransactionSync", duration)

	if c.vu != nil {
		rootTS := c.runtimeTagSet()
		if rootTS != nil {
			metrics.PushIfNotDone(c.vu.Context(), c.vu.State().Samples, metrics.Sample{
				TimeSeries: metrics.TimeSeries{
					Metric: c.metrics.TimeToMine,
					Tags:   rootTS,
				},
				Value: float64(duration / time.Millisecond),
				Time:  time.Now(),
			})
		}
	}

	return NewReceipt(receipt), nil
}

// sendTransactionSync wraps eth_sendRawTransactionSync but avoids sending a nil timeout parameter,
// which some nodes reject by expecting a single argument.
func (c *Client) sendTransactionSync(ctx context.Context, tx *types.Transaction, timeout *time.Duration) (*types.Receipt, error) {
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	var receipt types.Receipt

	if timeout == nil {
		if err := c.rpcClient.CallContext(ctx, &receipt, "eth_sendRawTransactionSync", hexutil.Bytes(raw)); err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		return &receipt, nil
	}

	var timeoutMillis *hexutil.Uint64

	if timeoutMs := timeout.Milliseconds(); timeoutMs > 0 {
		msValue := hexutil.Uint64(timeoutMs) //nolint:gosec // Timeout is user-controlled and bounded.
		timeoutMillis = &msValue
	}

	if err := c.rpcClient.CallContext(ctx, &receipt, "eth_sendRawTransactionSync", hexutil.Bytes(raw), timeoutMillis); err != nil { //nolint:wsl
		return nil, fmt.Errorf("%w", err)
	}

	return &receipt, nil
}

// SendTransactionAndWaitReceipt signs, sends and waits for the transaction receipt using
// eth_sendRawTransaction + polling, rather than eth_sendRawTransactionSync.
// This is useful for nodes that don't support the sync RPC method.
func (c *Client) SendTransactionAndWaitReceipt(transaction Transaction) (*Receipt, error) {
	return c.sendTransactionAndWaitReceiptWithRetries(transaction, maxTxRetries)
}

// sendTransactionAndWaitReceiptWithRetries is the internal implementation with retry tracking.
func (c *Client) sendTransactionAndWaitReceiptWithRetries(transaction Transaction, retriesLeft int) (*Receipt, error) { //nolint:gocognit,funlen
	// Choose nonce if not provided (shared manager).
	if transaction.Nonce == 0 {
		nonce, err := globalNonceManager.Acquire(c, c.address)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire nonce: %w", err)
		}

		transaction.Nonce = nonce
	}

	typedTx, err := c.buildTypedTx(transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction: %w", err)
	}

	signer := types.LatestSignerForChainID(c.chainID)

	signedTx, err := types.SignTx(typedTx, signer, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	startTime := time.Now()

	// Send the transaction using eth_sendRawTransaction.
	sendStartTime := time.Now()
	err = c.client.SendTransaction(context.Background(), signedTx)
	c.reportCallMetrics("eth_sendRawTransaction", time.Since(sendStartTime))

	if err != nil && retriesLeft > 0 { //nolint: nestif
		if retriesLeft > 0 {
			switch retryAction(err) {
			case RetryWithNonce:
				// Refresh nonce and retry.
				refreshErr := globalNonceManager.Refresh(c, c.address)
				if refreshErr != nil {
					return nil, fmt.Errorf("failed to refresh nonce: %w", refreshErr)
				}

				transaction.Nonce = 0

				return c.sendTransactionAndWaitReceiptWithRetries(transaction, retriesLeft-1)

			case RetryWithGasPrice:
				// Bump gas price by 10% and retry.
				if transaction.GasFeeCap > 0 {
					transaction.GasFeeCap = transaction.GasFeeCap * 110 / 100
					transaction.GasTipCap = transaction.GasTipCap * 110 / 100
				} else {
					transaction.GasPrice = transaction.GasPrice * 110 / 100
				}

				return c.sendTransactionAndWaitReceiptWithRetries(transaction, retriesLeft-1)

			case NoRetry:
			}
		}

		c.recordError(err, "eth_sendRawTransaction")

		return nil, fmt.Errorf("failed to send transaction: %w", err)
	}

	// Poll for receipt using GetTransactionReceipt.
	txHash := signedTx.Hash().Hex()

	for {
		receipt, err := c.GetTransactionReceipt(txHash)
		if err != nil {
			if !errors.Is(err, errReceiptNotFound) {
				return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
			}
		}

		if receipt != nil {
			duration := time.Since(startTime)

			if c.vu != nil {
				rootTS := c.runtimeTagSet()
				if rootTS != nil {
					metrics.PushIfNotDone(c.vu.Context(), c.vu.State().Samples, metrics.Sample{
						TimeSeries: metrics.TimeSeries{
							Metric: c.metrics.TimeToMine,
							Tags:   rootTS,
						},
						Value: float64(duration / time.Millisecond),
						Time:  time.Now(),
					})
				}
			}

			return receipt, nil
		}

		pollInterval := 100 * time.Millisecond
		time.Sleep(pollInterval)
	}
}

// BatchCallSync batches multiple calls via Multicall3's aggregate3 function.
// It encodes the calls, sends them as a single transaction, and returns the receipt.
func (c *Client) BatchCallSync(multicallAddr string, calls []Call3, opts TxnOpts) (*Receipt, error) {
	if len(calls) == 0 {
		return nil, errNoCallsProvided
	}

	input, err := encodeAggregate3(calls)
	if err != nil {
		return nil, fmt.Errorf("failed to encode aggregate3 call: %w", err)
	}

	// Build transaction to Multicall3.
	transaction := Transaction{
		To:         multicallAddr,
		Input:      input,
		GasPrice:   opts.GasPrice,
		Gas:        opts.GasLimit,
		Value:      int64(opts.Value), //nolint:gosec // Value is bounded by uint64.
		Nonce:      opts.Nonce,
		AccessList: opts.AccessList,
	}

	return c.SendTransactionSync(transaction)
}

// encodeAggregate3 encodes calls for Multicall3's aggregate3 function.
func encodeAggregate3(calls []Call3) ([]byte, error) {
	// Define the aggregate3 ABI.
	const aggregate3ABI = `[{"inputs":[{"components":[{"name":"target","type":"address"},{"name":"allowFailure","type":"bool"},{"name":"callData","type":"bytes"}],"name":"calls","type":"tuple[]"}],"name":"aggregate3","outputs":[{"components":[{"name":"success","type":"bool"},{"name":"returnData","type":"bytes"}],"name":"returnData","type":"tuple[]"}],"stateMutability":"payable","type":"function"}]`

	parsedABI, err := abi.JSON(strings.NewReader(aggregate3ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse aggregate3 ABI: %w", err)
	}

	// Build call tuples.
	type call3Tuple struct {
		Target       common.Address
		AllowFailure bool
		CallData     []byte
	}

	callTuples := make([]call3Tuple, len(calls))
	for i, call := range calls {
		callTuples[i] = call3Tuple{
			Target:       common.HexToAddress(call.Target),
			AllowFailure: call.AllowFailure,
			CallData:     call.Calldata,
		}
	}

	packed, err := parsedABI.Pack("aggregate3", callTuples)
	if err != nil {
		return nil, fmt.Errorf("failed to pack aggregate3 call: %w", err)
	}

	return packed, nil
}

// BatchCallValueSync batches multiple calls with ETH values via Multicall3's aggregate3Value function.
// It encodes the calls, sends them as a single transaction with the sum of values, and returns the receipt.
func (c *Client) BatchCallValueSync(multicallAddr string, calls []Call3Value, opts TxnOpts) (*Receipt, error) {
	if len(calls) == 0 {
		return nil, errNoCallsProvided
	}

	var totalValue int64

	input, err := encodeAggregate3Value(calls, &totalValue)
	if err != nil {
		return nil, fmt.Errorf("failed to encode aggregate3Value call: %w", err)
	}

	// Build transaction to Multicall3 with the sum of all call values.
	transaction := Transaction{
		To:         multicallAddr,
		Input:      input,
		GasPrice:   opts.GasPrice,
		Gas:        opts.GasLimit,
		Value:      totalValue,
		Nonce:      opts.Nonce,
		AccessList: opts.AccessList,
	}

	return c.SendTransactionSync(transaction)
}

// encodeAggregate3Value encodes calls for Multicall3's aggregate3Value function.
func encodeAggregate3Value(calls []Call3Value, totalValue *int64) ([]byte, error) {
	// Define the aggregate3Value ABI.
	const aggregate3ValueABI = `[{"inputs":[{"components":[{"name":"target","type":"address"},{"name":"allowFailure","type":"bool"},{"name":"value","type":"uint256"},{"name":"callData","type":"bytes"}],"name":"calls","type":"tuple[]"}],"name":"aggregate3Value","outputs":[{"components":[{"name":"success","type":"bool"},{"name":"returnData","type":"bytes"}],"name":"returnData","type":"tuple[]"}],"stateMutability":"payable","type":"function"}]`

	parsedABI, err := abi.JSON(strings.NewReader(aggregate3ValueABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse aggregate3Value ABI: %w", err)
	}

	// Build call tuples.
	type call3ValueTuple struct {
		Target       common.Address
		AllowFailure bool
		Value        *big.Int
		CallData     []byte
	}

	callTuples := make([]call3ValueTuple, len(calls))
	for i, call := range calls {
		callTuples[i] = call3ValueTuple{
			Target:       common.HexToAddress(call.Target),
			AllowFailure: call.AllowFailure,
			Value:        big.NewInt(int64(call.Value)), //nolint:gosec // Value is bounded by uint64.
			CallData:     call.Calldata,
		}
		*totalValue += int64(call.Value) //nolint:gosec // Value is bounded by uint64.
	}

	packed, err := parsedABI.Pack("aggregate3Value", callTuples)
	if err != nil {
		return nil, fmt.Errorf("failed to pack aggregate3Value call: %w", err)
	}

	return packed, nil
}

// convertAccessList converts our AccessTuple slice to go-ethereum's types.AccessList.
func convertAccessList(accessList []AccessTuple) types.AccessList {
	if len(accessList) == 0 {
		return nil
	}

	result := make(types.AccessList, len(accessList))

	for tupleIdx, tuple := range accessList {
		storageKeys := make([]common.Hash, len(tuple.StorageKeys))
		for keyIdx, key := range tuple.StorageKeys {
			storageKeys[keyIdx] = common.HexToHash(key)
		}

		result[tupleIdx] = types.AccessTuple{
			Address:     common.HexToAddress(tuple.Address),
			StorageKeys: storageKeys,
		}
	}

	return result
}

// buildTypedTx converts a Transaction into a go-ethereum transaction, estimating gas if needed.
func (c *Client) buildTypedTx(transaction Transaction) (*types.Transaction, error) {
	gas := transaction.Gas
	if gas == 0 {
		estimatedGas, err := c.EstimateGas(transaction)
		if err != nil {
			return nil, fmt.Errorf("failed to estimate gas: %w", err)
		}

		gas = estimatedGas
	}

	// Handle contract creation: empty string To means nil address
	var toAddr *common.Address

	if transaction.To != "" {
		addr := common.HexToAddress(transaction.To)
		toAddr = &addr
	}

	accessList := convertAccessList(transaction.AccessList)

	// Use EIP-1559 (DynamicFeeTx) if fee cap/tip cap are set, or if access list is provided
	if transaction.GasFeeCap > 0 || transaction.GasTipCap > 0 || len(accessList) > 0 {
		gasTipCap := big.NewInt(0).SetUint64(transaction.GasTipCap)
		gasFeeCap := big.NewInt(0).SetUint64(transaction.GasFeeCap)

		// If GasPrice is set but not GasTipCap/GasFeeCap, use GasPrice for the FeeCap and 0 for the TipCap.
		if transaction.GasPrice > 0 && transaction.GasTipCap == 0 && transaction.GasFeeCap == 0 {
			gasTipCap = big.NewInt(0)
			gasFeeCap = big.NewInt(0).SetUint64(transaction.GasPrice)
		}

		return types.NewTx(&types.DynamicFeeTx{
			ChainID:    c.chainID,
			Nonce:      transaction.Nonce,
			GasTipCap:  gasTipCap,
			GasFeeCap:  gasFeeCap,
			Gas:        gas,
			To:         toAddr,
			Value:      big.NewInt(transaction.Value),
			Data:       transaction.Input,
			AccessList: accessList,
		}), nil
	}

	return types.NewTx(&types.LegacyTx{
		Nonce:    transaction.Nonce,
		GasPrice: big.NewInt(0).SetUint64(transaction.GasPrice),
		Gas:      gas,
		To:       toAddr,
		Value:    big.NewInt(transaction.Value),
		Data:     transaction.Input,
	}), nil
}

// signAndSendRaw builds, signs and sends a raw tx, returning the hash string.
// It includes retry logic for nonce and gas price errors.
func (c *Client) signAndSendRaw(transaction Transaction) (string, error) {
	return c.signAndSendRawWithRetries(transaction, maxTxRetries)
}

// signAndSendRawWithRetries is the internal implementation with retry tracking.
func (c *Client) signAndSendRawWithRetries(transaction Transaction, retriesLeft int) (string, error) {
	typedTx, err := c.buildTypedTx(transaction)
	if err != nil {
		return "", err
	}

	signer := types.LatestSignerForChainID(c.chainID)

	signedTx, err := types.SignTx(typedTx, signer, c.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	startTime := time.Now()
	err = c.client.SendTransaction(context.Background(), signedTx)
	c.reportCallMetrics("eth_sendRawTransaction", time.Since(startTime))

	// Handle retry based on error type.
	if retriesLeft > 0 { //nolint:nestif // Retry logic requires nested checks.
		switch retryAction(err) {
		case RetryWithNonce:
			// Refresh nonce and retry.
			if refreshErr := globalNonceManager.Refresh(c, c.address); refreshErr == nil {
				if newNonce, acquireErr := globalNonceManager.Acquire(c, c.address); acquireErr == nil {
					transaction.Nonce = newNonce

					return c.signAndSendRawWithRetries(transaction, retriesLeft-1)
				}
			}

		case RetryWithGasPrice:
			// Bump gas price by 10% and retry.
			if transaction.GasFeeCap > 0 {
				transaction.GasFeeCap = transaction.GasFeeCap * 110 / 100
				transaction.GasTipCap = transaction.GasTipCap * 110 / 100
			} else {
				transaction.GasPrice = transaction.GasPrice * 110 / 100
			}

			return c.signAndSendRawWithRetries(transaction, retriesLeft-1)

		case NoRetry:
		}
	}

	if err != nil {
		return "", fmt.Errorf("failed to send raw transaction: %w", err)
	}

	return signedTx.Hash().Hex(), nil
}

// RetryAction indicates what retry strategy to use for an error.
type RetryAction int

const (
	// NoRetry means the error is not retryable.
	NoRetry RetryAction = iota
	// RetryWithNonce means refresh nonce from chain and retry.
	RetryWithNonce
	// RetryWithGasPrice means increase gas price and retry.
	RetryWithGasPrice
)

// retryAction determines what retry strategy to use for an error.
func retryAction(err error) RetryAction {
	if err == nil {
		return NoRetry
	}

	errMsg := err.Error()
	// Nonce errors - refresh nonce and retry
	if errMsg == core.ErrNonceTooLow.Error() ||
		errMsg == core.ErrNonceTooHigh.Error() {
		return RetryWithNonce
	}

	// Gas price errors - increase gas price and retry
	if errMsg == txpool.ErrUnderpriced.Error() ||
		errMsg == txpool.ErrReplaceUnderpriced.Error() ||
		errMsg == core.ErrFeeCapTooLow.Error() {
		return RetryWithGasPrice
	}

	return NoRetry
}

// Accounts returns a list of addresses owned by client.
// This endpoint is not enabled in infrastructure providers.
func (c *Client) Accounts() ([]string, error) {
	var accounts []common.Address

	err := c.rpcClient.Call(&accounts, "eth_accounts")
	if err != nil {
		c.recordError(err, "eth_accounts")

		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}

	addresses := make([]string, len(accounts))
	for index, account := range accounts {
		addresses[index] = account.Hex()
	}

	return addresses, nil
}

// Print prints a message to stdout without a newline.
func (c *Client) Print(msg string) {
	fmt.Print(msg) //nolint:forbidigo // Intentional stdout print for k6 output.
}

// NewContract creates a new contract instance with the given ABI.
func (c *Client) NewContract(address string, abiStr string) (*Contract, error) {
	contractABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse abi: %w", err)
	}

	contractAddress := common.HexToAddress(address)

	return &Contract{
		abi:    &contractABI,
		client: c,
		addr:   contractAddress,
	}, nil
}

// DeployContract deploys a contract to the blockchain.
func (c *Client) DeployContract(abiStr string, bytecode string, args ...any) (*Receipt, error) {
	contractABI, err := abi.JSON(strings.NewReader(abiStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse abi: %w", err)
	}

	convertedArgs, err := convertArgs(&contractABI, "constructor", args)
	if err != nil {
		return nil, fmt.Errorf("failed to convert args: %w", err)
	}

	contractBytecode, err := hex.DecodeString(bytecode)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bytecode: %w", err)
	}

	input := contractBytecode

	if len(convertedArgs) > 0 && contractABI.Constructor.Inputs != nil {
		constructorArgs, packErr := contractABI.Constructor.Inputs.Pack(convertedArgs...)
		if packErr != nil {
			return nil, fmt.Errorf("failed to pack constructor args: %w", packErr)
		}

		input = append(input, constructorArgs...)
	}

	gasPrice, err := c.client.SuggestGasPrice(context.Background())
	if err != nil {
		c.recordError(err, "gas_price")

		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}

	deploymentTx := Transaction{
		Nonce:    0,
		GasPrice: gasPrice.Uint64(),
		Gas:      3_000_000,
		To:       "", // Contract creation.
		Value:    0,
		Input:    input,
	}

	return c.SendTransactionSync(deploymentTx)
}

// makeHandledPromise creates a promise and returns its resolve and reject methods,
// wrapped in such a way that it will block the eventloop from exiting before they are
// called even if the promise isn't resolved by the time the current script ends executing.
func (c *Client) makeHandledPromise() (*sobek.Promise, func(any), func(any)) {
	runtime := c.vu.Runtime()
	callback := c.vu.RegisterCallback()
	promise, resolve, reject := runtime.NewPromise()

	resolveFunc := func(value any) {
		callback(func() error {
			resolve(value)

			return nil
		})
	}

	rejectFunc := func(value any) {
		callback(func() error {
			reject(value)

			return nil
		})
	}

	return promise, resolveFunc, rejectFunc
}

// BlockMonitor handles block event processing and metrics.
type BlockMonitor struct {
	client        *Client
	batchSize     int
	events        chan *types.Header
	unsubscribe   func() error
	lastBlockTime time.Time
	wsClient      *ethclient.Client
}

// GetWallet returns wallet information (address and private key).
func (c *Client) GetWallet() (*WalletInfo, error) {
	if c.privateKey == nil {
		return nil, errWalletNotInitialized
	}

	privateKeyBytes := crypto.FromECDSA(c.privateKey)

	return &WalletInfo{
		Address:    c.address.Hex(),
		PrivateKey: hex.EncodeToString(privateKeyBytes),
	}, nil
}

// SetPrivateKey sets the private key for the client, updating the address accordingly.
func (c *Client) SetPrivateKey(privateKey string) error {
	// Remove 0x prefix if present.
	privateKeyHex := privateKey
	if len(privateKeyHex) > 2 && privateKeyHex[:2] == "0x" {
		privateKeyHex = privateKeyHex[2:]
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	privateKeyObj, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to create private key: %w", err)
	}

	address := crypto.PubkeyToAddress(privateKeyObj.PublicKey)
	c.privateKey = privateKeyObj
	c.address = address

	return nil
}

// WalletInfo contains wallet information exposed to JavaScript.
type WalletInfo struct {
	Address    string `js:"address"`
	PrivateKey string `js:"privateKey"`
}

func convertToWS(url string) string {
	if after, found := strings.CutPrefix(url, "http://"); found {
		return "ws://" + after
	}

	if after, found := strings.CutPrefix(url, "https://"); found {
		return "wss://" + after
	}

	return url
}

// NewBlockMonitor creates a new BlockMonitor for the client.
func (c *Client) NewBlockMonitor(batchSize int) *BlockMonitor {
	effectiveBatchSize := batchSize
	if effectiveBatchSize == 0 {
		effectiveBatchSize = 1
	}

	wsURL := convertToWS(c.opts.URL)

	wsClient, err := ethclient.Dial(wsURL)
	if err != nil {
		panic(fmt.Errorf("failed to create ws client: %w", err))
	}

	events := make(chan *types.Header)

	var sub ethereum.Subscription

	// Retry subscription with backoff.
	const maxRetries = 10

	for attempt := range maxRetries {
		sub, err = wsClient.SubscribeNewHead(context.Background(), events)
		if err == nil {
			break
		}

		if attempt < maxRetries-1 {
			waitTime := time.Duration(attempt+1) * 2 * time.Second                                                                       //nolint:gosec,mnd // Safe conversion and retry backoff.
			fmt.Printf("Failed to subscribe to newHeads (attempt %d/%d): %v. Retrying in %v...\n", attempt+1, maxRetries, err, waitTime) //nolint:forbidigo // Intentional stdout for retry logging.
			time.Sleep(waitTime)
		}
	}

	if err != nil {
		panic(fmt.Errorf("failed to subscribe to newHeads: %w", err))
	}

	unsubscribe := func() error {
		sub.Unsubscribe()

		return nil
	}

	return &BlockMonitor{
		client:      c,
		batchSize:   effectiveBatchSize,
		events:      events,
		unsubscribe: unsubscribe,
		wsClient:    wsClient,
	}
}

// ProcessBlockEvent processes incoming block headers from the WebSocket subscription and emits metrics.
// It is intended to be called periodically from a dedicated K6 scenario.
func (bm *BlockMonitor) ProcessBlockEvent() {
	select {
	case header := <-bm.events:
		bm.handleBlockHeader(header)

	case <-bm.getContextDone():
		bm.cleanup()
	}
}

func (bm *BlockMonitor) handleBlockHeader(header *types.Header) {
	const millisecondsPerSecond = 1000.0

	// Use block number as nanoseconds to ensure unique timestamps when multiple blocks share
	// the same second-level timestamp. Block timestamps are only second-granular, but InfluxDB
	// uses timestamp+tags as unique identifiers, causing data point overwrites without this.
	headerTimestamp := time.Unix(int64(header.Time), int64(header.Number.Uint64()%1_000_000_000)) //nolint:gosec // don't care about overflow

	if bm.lastBlockTime.IsZero() {
		bm.lastBlockTime = headerTimestamp

		return
	}

	timeDelta := headerTimestamp.Sub(bm.lastBlockTime)
	bm.lastBlockTime = headerTimestamp

	// Get full block to count transactions.
	startTime := time.Now()
	block, err := bm.wsClient.BlockByHash(context.Background(), header.Hash())
	bm.client.reportCallMetrics("eth_getBlockByHash", time.Since(startTime))

	if err != nil {
		fmt.Println("Error getting block:", err) //nolint:all // Intentional stdout for error logging.

		return
	}

	if block == nil {
		return
	}

	// Count only user transactions (standard EVM types 0x00-0x04).
	// Excludes Arbitrum system transactions (types 0x64+) from UOPS calculation.
	txs := block.Transactions()
	userTxCount := 0

	for _, tx := range txs {
		if tx.Type() <= types.SetCodeTxType {
			userTxCount++
		}
	}

	// Calculate user operations and block time.
	blockTimeMs := timeDelta.Seconds() * millisecondsPerSecond

	bm.emitBlockMetrics(block, userTxCount, blockTimeMs, headerTimestamp)
}

func (bm *BlockMonitor) emitBlockMetrics(block *types.Block, userTxCount int, blockTimeMs float64, blockTimestamp time.Time) {
	if bm.client.vu == nil {
		return
	}

	rootTS := bm.client.runtimeTagSet()
	if rootTS == nil {
		return
	}

	userOps := float64(userTxCount * bm.batchSize)

	// Emit all block metrics as connected samples.
	samples := []metrics.Sample{
		{
			TimeSeries: metrics.TimeSeries{
				Metric: bm.client.metrics.BlockCount,
				Tags:   rootTS,
			},
			Value: float64(1),
			Time:  blockTimestamp,
		},
		{
			TimeSeries: metrics.TimeSeries{
				Metric: bm.client.metrics.BlockNumber,
				Tags:   rootTS,
			},
			Value: float64(block.NumberU64()),
			Time:  blockTimestamp,
		},
		{
			TimeSeries: metrics.TimeSeries{
				Metric: bm.client.metrics.BlockTransactions,
				Tags:   rootTS,
			},
			Value: float64(userTxCount),
			Time:  blockTimestamp,
		},
		{
			TimeSeries: metrics.TimeSeries{
				Metric: bm.client.metrics.GasUsed,
				Tags:   rootTS,
			},
			Value: float64(block.GasUsed()),
			Time:  blockTimestamp,
		},
		{
			TimeSeries: metrics.TimeSeries{
				Metric: bm.client.metrics.BlockUserOps,
				Tags:   rootTS,
			},
			Value: userOps,
			Time:  blockTimestamp,
		},
		{
			TimeSeries: metrics.TimeSeries{
				Metric: bm.client.metrics.BlockTime,
				Tags:   rootTS,
			},
			Value: blockTimeMs,
			Time:  blockTimestamp,
		},
	}

	connectedSamples := metrics.ConnectedSamples{
		Samples: samples,
		Tags:    rootTS,
		Time:    blockTimestamp,
	}

	metrics.PushIfNotDone(bm.client.vu.Context(), bm.client.vu.State().Samples, connectedSamples)
}

func (bm *BlockMonitor) cleanup() {
	if bm.unsubscribe != nil {
		if err := bm.unsubscribe(); err != nil {
			fmt.Println("Error unsubscribing from block monitor:", err) //nolint:all // Intentional stdout.
		}
	}

	if bm.wsClient != nil {
		bm.wsClient.Close()
	}
}

func (bm *BlockMonitor) getContextDone() <-chan struct{} {
	if bm.client.vu != nil {
		return bm.client.vu.Context().Done()
	}

	// Return a channel that never closes if vu is nil.
	return make(chan struct{})
}
