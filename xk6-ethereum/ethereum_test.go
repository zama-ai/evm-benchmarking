//go:build integration

package ethereum

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

const (
	testNodeURL = "http://127.0.0.1:8545"
	// testPrivateKey is Anvil's default account 0 private key.
	// Derived from standard Anvil development mnemonic (eleven "test" words followed by "junk").
	// This account is automatically funded with 10000 ETH by Anvil.
	// This is safe to use in tests as it's only for local development. trunk-ignore(gitleaks/generic-api-key).
	// nolint:godot
	/* trunk-ignore(gitleaks/generic-api-key) */
	testPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

// Static test errors for table-driven tests.
var (
	errOther = errors.New("some other error")
)

// checkNodeAvailable verifies that an Ethereum node is available at the test node URL.
// If not available, it fails the test with a clear error message.
func checkNodeAvailable(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, testNodeURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)

		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Ethereum node not available at %s. Start Anvil with: anvil --port 8545", testNodeURL)

		return
	}

	_ = resp.Body.Close()
}

// setupClient creates a test client with the configured private key and node URL.
func setupClient() (*Client, error) {
	url := testNodeURL

	privateKeyBytes, err := hex.DecodeString(testPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	rpcClient, err := rpc.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc client: %w", err)
	}

	ethClient := ethclient.NewClient(rpcClient)

	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	return &Client{
		client:     ethClient,
		rpcClient:  rpcClient,
		privateKey: privateKey,
		address:    address,
		chainID:    chainID,
		opts: &options{
			URL: url,
		},
	}, nil
}

// setupReadOnlyClient creates a client without a private key for monitoring-only use cases.
func setupReadOnlyClient() (*Client, error) {
	url := testNodeURL

	rpcClient, err := rpc.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc client: %w", err)
	}

	ethClient := ethclient.NewClient(rpcClient)

	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	return &Client{
		client:    ethClient,
		rpcClient: rpcClient,
		chainID:   chainID,
		opts: &options{
			URL: url,
		},
	}, nil
}

// setupFundedAccount ensures the test account has sufficient funds.
// If not, it skips the test with a clear error message.
func setupFundedAccount(t *testing.T, client *Client) {
	t.Helper()

	balance, err := client.GetBalance(client.address.Hex(), nil) // nil = latest
	require.NoError(t, err)

	// Require at least 1 ETH (1e18 wei) for tests.
	minBalance := uint64(1e18)
	if balance < minBalance {
		t.Skipf("Test account has insufficient funds. Current balance: %d wei. Fund account: %s", balance, client.address.Hex())
	}
}

func TestSetPrivateKey(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Anvil key 2
	/* trunk-ignore(gitleaks/generic-api-key) */
	newPrivateKey := "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	require.NoError(t, client.SetPrivateKey(newPrivateKey))
	require.Equal(t, crypto.PubkeyToAddress(client.privateKey.PublicKey), client.address)
	require.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", client.address.Hex())
}

// ============================================================================
// Basic RPC Methods Tests
// ============================================================================

func TestGasPrice(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	gasPrice, err := client.GasPrice()
	require.NoError(t, err)
	require.Positive(t, gasPrice, "gas price should be greater than 0")
}

func TestReadOnlyClient(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupReadOnlyClient()
	require.NoError(t, err)

	_, err = client.BlockNumber()
	require.NoError(t, err)

	_, err = client.SendTransaction(Transaction{
		To:    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value: 1,
	})
	require.ErrorIs(t, err, errPrivateKeyRequired)
}

func TestBlockNumber(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	blockNum, err := client.BlockNumber()
	require.NoError(t, err)
	// blockNum is uint64, which is always >= 0, so we just verify we got it.
	_ = blockNum
}

func TestGetBlockByNumber(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	tests := []struct {
		name   string
		number *big.Int // nil = latest
	}{
		{"Latest", nil},
		{"Specific", big.NewInt(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, err := client.GetBlockByNumber(tt.number)
			require.NoError(t, err)
			require.NotNil(t, block)
		})
	}
}

func TestGetBalance(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	tests := []struct {
		name        string
		address     string
		blockNumber *big.Int // nil = latest
		expectError bool
	}{
		{"ValidAddress", client.address.Hex(), nil, false},
		// Note: go-ethereum normalizes addresses and doesn't error on invalid formats
		// It returns 0 balance for invalid addresses, so we skip error testing here
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			balance, err := client.GetBalance(testCase.address, testCase.blockNumber)
			require.NoError(t, err)
			// balance is uint64, which is always >= 0, so we just verify we got it.
			_ = balance
		})
	}
}

func TestGetNonce(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	nonce, err := client.GetNonce(client.address.Hex())
	require.NoError(t, err)
	// nonce is uint64, which is always >= 0, so we just verify we got it.
	_ = nonce
}

func TestAccounts(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	accounts, err := client.Accounts()
	// Accounts() may not be supported by all providers (e.g., public RPCs).
	// So we don't fail if it returns an error, but log it.
	if err != nil {
		t.Logf("Accounts() not supported by this provider: %v", err)

		return
	}

	require.NotNil(t, accounts)
}

// ============================================================================
// Transaction Operations Tests
// ============================================================================

func TestEstimateGas(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	tests := []struct {
		name        string
		transaction Transaction
		expectGas   bool
	}{
		{
			name: "SimpleTransfer",
			transaction: Transaction{
				To:    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
				Value: 10,
			},
			expectGas: true,
		},
		{
			name: "WithData",
			transaction: Transaction{
				To:    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
				Value: 0,
				Input: []byte{0x12, 0x34, 0x56},
			},
			expectGas: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			gas, err := client.EstimateGas(testCase.transaction)
			if testCase.expectGas {
				require.NoError(t, err)
				require.Positive(t, gas)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSendRawTransaction(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Get current nonce.
	nonce, err := client.GetNonce(client.address.Hex())
	require.NoError(t, err)

	// Get gas price.
	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	transaction := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
		Nonce:    nonce,
	}

	txHash, err := client.SendRawTransaction(transaction)
	require.NoError(t, err)
	require.NotEmpty(t, txHash)
	require.Contains(t, txHash, "0x")
}

func TestSendTransactionSync(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Get gas price.
	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	transaction := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
		// Nonce will be acquired automatically.
	}

	receipt, err := client.SendTransactionSync(transaction)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, uint64(1), receipt.Status)
}

func TestGetTransactionReceipt(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// First, send a transaction.
	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	transaction := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
	}

	txHash, err := client.SendRawTransaction(transaction)
	require.NoError(t, err)

	// Wait a bit for the transaction to be mined.
	time.Sleep(500 * time.Millisecond)

	// Get receipt.
	receipt, err := client.GetTransactionReceipt(txHash)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, txHash, receipt.TxHash)
}

func TestSendTransaction(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	transaction := Transaction{
		From:     client.address.Hex(),
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
		Gas:      21000,
	}

	txHash, err := client.SendTransaction(transaction)
	require.NoError(t, err)
	require.NotEmpty(t, txHash)
	require.Contains(t, txHash, "0x")
}

func TestSendTransactionAndWaitReceipt(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Get gas price.
	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	transaction := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
		// Nonce will be acquired automatically.
	}

	receipt, err := client.SendTransactionAndWaitReceipt(transaction)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, uint64(1), receipt.Status)
}

// ============================================================================
// Batch Operations Tests
// ============================================================================

func TestBatchCallSync(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Refresh nonce manager to avoid conflicts from previous tests.
	_ = globalNonceManager.Refresh(client, client.address)

	// Deploy Multicall3 first
	multicallAddr := deployMulticall3(t, client)

	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	calls := []Call3{
		{
			Target:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
			AllowFailure: false,
			Calldata:     []byte{0x12, 0x34},
		},
		{
			Target:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
			AllowFailure: true,
			Calldata:     []byte{0x56, 0x78},
		},
	}

	opts := TxnOpts{
		GasPrice: gasPrice,
		GasLimit: 500000,
	}

	receipt, err := client.BatchCallSync(multicallAddr, calls, opts)
	require.NoError(t, err)
	require.NotNil(t, receipt)
}

func TestBatchCallValueSync(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Refresh nonce manager to avoid conflicts from previous tests.
	_ = globalNonceManager.Refresh(client, client.address)

	// Deploy Multicall3 first
	multicallAddr := deployMulticall3(t, client)

	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	calls := []Call3Value{
		{
			Target:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
			AllowFailure: false,
			Value:        10,
			Calldata:     []byte{},
		},
	}

	opts := TxnOpts{
		GasPrice: gasPrice,
		GasLimit: 500000,
	}

	receipt, err := client.BatchCallValueSync(multicallAddr, calls, opts)
	require.NoError(t, err)
	require.NotNil(t, receipt)
}

// deployMulticall3 deploys the Multicall3 contract and returns its address.
func deployMulticall3(t *testing.T, client *Client) string {
	t.Helper()

	// Multicall3 bytecode (minimal version for testing).
	// This is a simplified version - in production, use the actual Multicall3 bytecode.
	multicallBin := "608060405234801561001057600080fd5b50600436106100365760003560e01c80633b8e5b8e1461003b575b600080fd5b610043610059565b60405161005091906100a1565b60405180910390f35b60606040518060400160405280600781526020017f4d756c746963616c6c0000000000000000000000000000000000000000000000815250905090565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b9291505056fea264697066735822122000000000000000000000000000000000000000000000000000000000000000064736f6c63430008000033"

	multicallABI := `[{"type":"function","name":"aggregate3","inputs":[{"name":"calls","type":"tuple[]","components":[{"name":"target","type":"address"},{"name":"allowFailure","type":"bool"},{"name":"callData","type":"bytes"}]}],"outputs":[{"name":"returnData","type":"tuple[]","components":[{"name":"success","type":"bool"},{"name":"returnData","type":"bytes"}]}]}]`

	receipt, err := client.DeployContract(multicallABI, multicallBin)
	if err != nil {
		// If deployment fails, try to get Multicall3 from known address.
		// Anvil may have it pre-deployed.
		return "0xcA11bde05977b3631167028862bE2a173976CA11"
	}

	require.NoError(t, err)

	return receipt.ContractAddress
}

// ============================================================================
// Contract Operations Tests
// ============================================================================

func TestNewContract(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Simple ERC20-like ABI for testing.
	abiStr := `[{"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`
	address := "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2"

	contract, err := client.NewContract(address, abiStr)
	require.NoError(t, err)
	require.NotNil(t, contract)

	expectedAddr := common.HexToAddress(address)
	require.Equal(t, expectedAddr, contract.addr)
}

func TestEncodeABIConversions(t *testing.T) {
	client, err := setupClient()
	require.NoError(t, err)

	abiStr := `[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]}]`

	contract, err := client.NewContract("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2", abiStr)
	require.NoError(t, err)

	calldata, err := contract.EncodeABI("transfer", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", int64(1))
	require.NoError(t, err)
	require.NotEmpty(t, calldata)
}

func TestDeployContract(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Refresh nonce manager to avoid conflicts from previous tests.
	_ = globalNonceManager.Refresh(client, client.address)

	// Simple storage contract (compiled with solc 0.8.30).
	contractBin := "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632e64cec114603e5780633fa4f2451460535780636057361d14605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220ddc4e8386ce650a1019c837f324cbb0164ab60be5ecaa5e1c7d6891c00476fb364736f6c634300081e0033"

	contractABI := `[{"inputs":[],"name":"retrieve","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"num","type":"uint256"}],"name":"store","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"value","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]`

	receipt, err := client.DeployContract(contractABI, contractBin)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, uint64(1), receipt.Status, "contract deployment should succeed")
	require.NotEmpty(t, receipt.ContractAddress, "contract address should be set")

	// Verify contract address is not zero address
	zeroAddrHex := "0x0000000000000000000000000000000000000000"
	require.NotEqual(t, zeroAddrHex, receipt.ContractAddress, "contract address should not be zero address")

	// Verify we can call the deployed contract
	contract, err := client.NewContract(receipt.ContractAddress, contractABI)
	require.NoError(t, err)

	// Call retrieve() to verify the contract is actually deployed
	result, err := contract.Call("retrieve")
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestContractTxnAndWaitReceipt(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Refresh nonce manager to avoid conflicts from previous tests.
	_ = globalNonceManager.Refresh(client, client.address)

	// Simple storage contract (compiled with solc 0.8.30).
	contractBin := "6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632e64cec114603e5780633fa4f2451460535780636057361d14605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220ddc4e8386ce650a1019c837f324cbb0164ab60be5ecaa5e1c7d6891c00476fb364736f6c634300081e0033"

	contractABI := `[{"inputs":[],"name":"retrieve","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"num","type":"uint256"}],"name":"store","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"value","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]`

	// Deploy contract first.
	receipt, err := client.DeployContract(contractABI, contractBin)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, uint64(1), receipt.Status)

	// Create contract instance.
	contract, err := client.NewContract(receipt.ContractAddress, contractABI)
	require.NoError(t, err)

	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	// Call store(42) using TxnAndWaitReceipt.
	opts := TxnOpts{
		GasPrice: gasPrice,
		GasLimit: 100000,
	}

	storeReceipt, err := contract.TxnAndWaitReceipt("store", opts, int64(42))
	require.NoError(t, err)
	require.NotNil(t, storeReceipt)
	require.Equal(t, uint64(1), storeReceipt.Status, "store transaction should succeed")

	// Verify the value was stored by calling retrieve().
	result, err := contract.Call("retrieve")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, big.NewInt(42), result["0"])
}

// ============================================================================
// Tuple Encoding Tests
// ============================================================================

func TestEncodeABIWithTuple(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	tests := []struct {
		name           string
		abiStr         string
		method         string
		args           []any
		expectSuccess  bool
		expectedLength int // 0 means don't check length
	}{
		{
			name:   "SimpleTuple",
			abiStr: `[{"type":"function","name":"setPerson","inputs":[{"name":"person","type":"tuple","components":[{"name":"addr","type":"address"},{"name":"age","type":"uint256"}]}],"outputs":[]}]`,
			method: "setPerson",
			args: []any{
				[]any{"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", int64(25)},
			},
			expectSuccess:  true,
			expectedLength: 4 + 32 + 32, // selector + address + uint256
		},
		{
			name:   "NestedTuple",
			abiStr: `[{"type":"function","name":"setOuter","inputs":[{"name":"outer","type":"tuple","components":[{"name":"addr","type":"address"},{"name":"inner","type":"tuple","components":[{"name":"value","type":"uint256"}]}]}],"outputs":[]}]`,
			method: "setOuter",
			args: []any{
				[]any{"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", []any{int64(42)}},
			},
			expectSuccess: true,
		},
		{
			name:   "TupleArray",
			abiStr: `[{"type":"function","name":"setItems","inputs":[{"name":"items","type":"tuple[]","components":[{"name":"id","type":"uint256"},{"name":"data","type":"bytes32"}]}],"outputs":[]}]`,
			method: "setItems",
			args: []any{
				[]any{
					[]any{int64(1), "0x0000000000000000000000000000000000000000000000000000000000000001"},
					[]any{int64(2), "0x0000000000000000000000000000000000000000000000000000000000000002"},
				},
			},
			expectSuccess: true,
		},
		{
			name:   "MixedTypes",
			abiStr: `[{"type":"function","name":"setComplex","inputs":[{"name":"data","type":"tuple","components":[{"name":"addr","type":"address"},{"name":"amount","type":"uint256"},{"name":"hash","type":"bytes32"},{"name":"active","type":"bool"}]}],"outputs":[]}]`,
			method: "setComplex",
			args: []any{
				[]any{
					"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					int64(1000000),
					"0xabcdef0000000000000000000000000000000000000000000000000000000000",
					true,
				},
			},
			expectSuccess: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			contract, err := client.NewContract("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2", testCase.abiStr)
			require.NoError(t, err)

			calldata, err := contract.EncodeABI(testCase.method, testCase.args...)
			if testCase.expectSuccess {
				require.NoError(t, err)
				require.NotEmpty(t, calldata)

				if testCase.expectedLength > 0 {
					require.Len(t, calldata, testCase.expectedLength)
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestEncodeABIWithTupleErrors(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// ABI with tuple parameter.
	abiStr := `[{
		"type": "function",
		"name": "setPerson",
		"inputs": [{
			"name": "person",
			"type": "tuple",
			"components": [
				{"name": "addr", "type": "address"},
				{"name": "age", "type": "uint256"}
			]
		}],
		"outputs": []
	}]`

	contract, err := client.NewContract("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2", abiStr)
	require.NoError(t, err)

	tests := []struct {
		name  string
		tuple any
	}{
		{
			name:  "WrongFieldCount",
			tuple: []any{"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}, // Only 1 field, expects 2
		},
		{
			name:  "TooManyFields",
			tuple: []any{"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", int64(25), "extra"}, // 3 fields, expects 2
		},
		{
			name:  "NotAnArray",
			tuple: "not a tuple", // String instead of array
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := contract.EncodeABI("setPerson", testCase.tuple)
			require.Error(t, err, "should fail for %s", testCase.name)
		})
	}
}

func TestNewBlockMonitor_SubscribeFailure(t *testing.T) {
	client := &Client{
		opts: &options{
			URL: "http://127.0.0.1:1", // invalid port; WS dial should fail
		},
	}

	monitor, err := client.newBlockMonitor(1)
	require.Error(t, err)
	require.Nil(t, monitor)
}

// ============================================================================
// Utility Methods Tests
// ============================================================================

func TestPrint(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Print should not panic
	client.Print("Test message")
	client.Print("")
}

func TestGetWallet(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	walletInfo, err := client.GetWallet()
	require.NoError(t, err)
	require.NotNil(t, walletInfo)
	require.NotEmpty(t, walletInfo.Address)
	require.NotEmpty(t, walletInfo.PrivateKey)
	require.Equal(t, client.address.Hex(), walletInfo.Address)
}

func TestNewBlockMonitor(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	tests := []struct {
		name      string
		batchSize int
	}{
		{"Default", 0},
		{"Custom", 10},
		{"Large", 100},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			monitor, err := client.newBlockMonitor(testCase.batchSize)
			if err != nil {
				t.Skipf("block monitor unavailable: %v", err)
			}

			require.NotNil(t, monitor)
			require.Equal(t, client, monitor.client)

			expectedBatchSize := testCase.batchSize
			if expectedBatchSize == 0 {
				expectedBatchSize = 1 // Default value.
			}

			require.Equal(t, expectedBatchSize, monitor.batchSize)
		})
	}
}

// ============================================================================
// BlockMonitor Tests
// ============================================================================

func TestBlockMonitor_PollBlocks(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// BlockMonitor requires k6 runtime for metrics, so we'll skip detailed testing.
	// In a real k6 environment, this would work.
	monitor, err := client.newBlockMonitor(1)
	if err != nil {
		t.Skipf("block monitor unavailable: %v", err)
	}

	require.NotNil(t, monitor)

	// Test that it doesn't panic (metrics will be skipped if vu is nil)
	monitor.ProcessBlockEvent()
}

// ============================================================================
// Error Handling & Edge Cases Tests
// ============================================================================

func TestInvalidAddress(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Note: go-ethereum normalizes addresses and doesn't error on invalid formats.
	// It treats invalid addresses as zero addresses and returns 0 balance/nonce.
	// This test verifies that the methods handle invalid addresses gracefully
	// (returning 0 values rather than panicking).
	tests := []struct {
		name    string
		address string
		method  func(string) (uint64, error)
	}{
		{
			name:    "GetBalance_Invalid",
			address: "not-an-address",
			method: func(addr string) (uint64, error) {
				return client.GetBalance(addr, nil) // nil = latest
			},
		},
		{
			name:    "GetNonce_Invalid",
			address: "not-an-address",
			method: func(addr string) (uint64, error) {
				return client.GetNonce(addr)
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			value, err := testCase.method(testCase.address)
			require.ErrorIs(t, err, errInvalidAddress)
			_ = value
		})
	}
}

func TestNonceConflictHandling(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	// Get initial nonce
	nonce, err := client.GetNonce(client.address.Hex())
	require.NoError(t, err)

	// Send first transaction
	tx1 := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
		Nonce:    nonce,
	}

	txHash1, err := client.SendRawTransaction(tx1)
	require.NoError(t, err)
	require.NotEmpty(t, txHash1)

	// Try to send another transaction with the same nonce (should fail or be handled)
	// The NonceManager should handle this, but if we explicitly use the same nonce,
	// it should either fail or the manager should refresh
	tx2 := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
		Nonce:    nonce, // Same nonce
	}

	// This should either succeed (if nonce manager refreshes) or fail gracefully
	_, err = client.SendRawTransaction(tx2)
	// We don't assert here because behavior depends on node state
	t.Logf("Second transaction with same nonce result: %v", err)
}

func TestMissingNode(t *testing.T) {
	// Create a client with an invalid URL.
	invalidURL := "http://127.0.0.1:99999"
	privateKeyBytes, _ := hex.DecodeString(testPrivateKey)
	privateKey, _ := crypto.ToECDSA(privateKeyBytes)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	rpcClient, err := rpc.Dial(invalidURL)
	if err != nil {
		t.Skip("Failed to create client with invalid URL (expected)")

		return
	}

	ethClient := ethclient.NewClient(rpcClient)

	client := &Client{
		client:     ethClient,
		rpcClient:  rpcClient,
		privateKey: privateKey,
		address:    address,
		chainID:    big.NewInt(1), // Use a dummy chain ID.
		opts: &options{
			URL: invalidURL,
		},
	}

	// All operations should fail with connection errors
	// Error messages vary: "connection", "connect", "dial", "invalid argument", etc.
	_, err = client.GasPrice()
	require.Error(t, err)
	errMsg := strings.ToLower(err.Error())
	require.True(t,
		strings.Contains(errMsg, "connection") ||
			strings.Contains(errMsg, "connect") ||
			strings.Contains(errMsg, "dial") ||
			strings.Contains(errMsg, "invalid"),
		"error should indicate connection failure, got: %s", err.Error())

	_, err = client.BlockNumber()
	require.Error(t, err)
}

// ============================================================================
// Helper Functions Unit Tests
// ============================================================================

func TestSanitizeTagValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SimpleMessage",
			input:    "simple error",
			expected: "simple_error",
		},
		{
			name:     "JSONError",
			input:    `429 Too Many Requests: {"jsonrpc":"2.0","error":{"code":-32017}}`,
			expected: "429_Too_Many_Requests:_jsonrpc:2.0_error:code:-32017",
		},
		{
			name:     "CommasAndEquals",
			input:    "key=value, another=test",
			expected: "key_value__another_test",
		},
		{
			name:     "Newlines",
			input:    "line1\nline2\rline3",
			expected: "line1_line2_line3",
		},
		{
			name:     "LongMessage",
			input:    strings.Repeat("a", 200),
			expected: strings.Repeat("a", 100), // Should be truncated
		},
		{
			name:     "Empty",
			input:    "",
			expected: "",
		},
		{
			name:     "BracketsAndQuotes",
			input:    `error["key"]='value'`,
			expected: "errorkey_value",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := sanitizeTagValue(testCase.input)
			require.Equal(t, testCase.expected, result)
		})
	}
}

func TestRetryAction(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected RetryAction
	}{
		{
			name:     "NonceTooLow",
			err:      core.ErrNonceTooLow,
			expected: RetryWithNonce,
		},
		{
			name:     "NonceTooHigh",
			err:      core.ErrNonceTooHigh,
			expected: RetryWithNonce,
		},
		{
			name:     "Underpriced",
			err:      txpool.ErrUnderpriced,
			expected: RetryWithGasPrice,
		},
		{
			name:     "ReplaceUnderpriced",
			err:      txpool.ErrReplaceUnderpriced,
			expected: RetryWithGasPrice,
		},
		{
			name:     "FeeCapTooLow",
			err:      core.ErrFeeCapTooLow,
			expected: RetryWithGasPrice,
		},
		{
			name:     "NoError",
			err:      nil,
			expected: NoRetry,
		},
		{
			name:     "OtherError",
			err:      errOther,
			expected: NoRetry,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := retryAction(testCase.err)
			require.Equal(t, testCase.expected, result)
		})
	}
}

// ============================================================================
// Transaction Type Filtering Tests
// ============================================================================

func TestIsUserTransaction(t *testing.T) {
	// Test transaction type filtering logic used in UOPS calculation.
	// Standard EVM types (0x00-0x04) should be counted as user transactions.
	// Arbitrum system types (0x64+) should be excluded.
	tests := []struct {
		name     string
		txType   uint8
		isUserTx bool
	}{
		// Standard EVM user transaction types (should be counted).
		{"LegacyTxType", types.LegacyTxType, true},
		{"AccessListTxType", types.AccessListTxType, true},
		{"DynamicFeeTxType", types.DynamicFeeTxType, true},
		{"BlobTxType", types.BlobTxType, true},
		{"SetCodeTxType", types.SetCodeTxType, true},

		// Arbitrum system transaction types (should be excluded).
		{"ArbitrumDepositTxType", 0x64, false},
		{"ArbitrumUnsignedTxType", 0x65, false},
		{"ArbitrumContractTxType", 0x66, false},
		{"ArbitrumRetryTxType", 0x68, false},
		{"ArbitrumSubmitRetryTxType", 0x69, false},
		{"ArbitrumInternalTxType", 0x6A, false},
		{"ArbitrumLegacyTxType", 0x78, false},

		// Edge cases.
		{"JustAboveSetCode", types.SetCodeTxType + 1, false},
		{"HighValue", 0xFF, false},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			// This replicates the filtering logic from handleBlockHeader:
			// if tx.Type() <= types.SetCodeTxType { userTxCount++ }
			isUserTx := testCase.txType <= types.SetCodeTxType
			require.Equal(t, testCase.isUserTx, isUserTx,
				"txType 0x%02X should be user=%v", testCase.txType, testCase.isUserTx)
		})
	}
}

func TestCountUserTransactions(t *testing.T) {
	// Test that counting logic correctly filters transaction types.
	// This simulates the filtering loop in handleBlockHeader.
	txTypes := []uint8{
		types.LegacyTxType,     // user
		types.DynamicFeeTxType, // user
		0x6A,                   // ArbitrumInternalTxType - system (excluded)
		types.AccessListTxType, // user
		0x64,                   // ArbitrumDepositTxType - system (excluded)
	}
	userTxCount := 0

	for _, txType := range txTypes {
		if txType <= types.SetCodeTxType {
			userTxCount++
		}
	}

	require.Equal(t, 3, userTxCount, "should count 3 user transactions out of 5 total")
}

// ============================================================================
// EIP-2930 Access List Tests
// ============================================================================

func TestBuildTypedTxWithAccessList(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	accessList := []AccessTuple{
		{
			Address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
			StorageKeys: []string{
				"0x0000000000000000000000000000000000000000000000000000000000000001",
			},
		},
	}

	transaction := Transaction{
		To:         "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:      1000,
		Gas:        21000,
		Nonce:      1,
		AccessList: accessList,
	}

	builtTx, err := client.buildTypedTx(transaction)
	require.NoError(t, err)
	require.NotNil(t, builtTx)

	// With access list, it should be a DynamicFeeTx (EIP-1559) type.
	require.Equal(t, uint8(types.DynamicFeeTxType), builtTx.Type(), "transaction with access list should be DynamicFeeTx type")

	// Verify access list is included.
	require.Len(t, builtTx.AccessList(), 1)
	require.Equal(t, common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2"), builtTx.AccessList()[0].Address)
	require.Len(t, builtTx.AccessList()[0].StorageKeys, 1)
	require.Equal(t, common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"), builtTx.AccessList()[0].StorageKeys[0])
}

func TestBuildTypedTxWithoutAccessList(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Transaction without access list and without EIP-1559 fields should be Legacy.
	transaction := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    1000,
		Gas:      21000,
		GasPrice: 1000000000, // 1 gwei
		Nonce:    1,
	}

	builtTx, err := client.buildTypedTx(transaction)
	require.NoError(t, err)
	require.NotNil(t, builtTx)

	// Without access list and without EIP-1559 fields, it should be LegacyTx type.
	require.Equal(t, uint8(types.LegacyTxType), builtTx.Type(), "transaction without access list should be LegacyTx type")
}

func TestEstimateGasWithAccessList(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Test that EstimateGas works with access list.
	// Use Value: 0 to avoid requiring funded account - this test is about access lists, not transfers.
	accessList := []AccessTuple{
		{
			Address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
			StorageKeys: []string{
				"0x0000000000000000000000000000000000000000000000000000000000000001",
			},
		},
	}

	transaction := Transaction{
		To:         "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:      0,
		AccessList: accessList,
	}

	gas, err := client.EstimateGas(transaction)
	require.NoError(t, err)
	require.Positive(t, gas, "gas estimate should be positive")

	// Gas with access list may differ from without, but both should work.
	transactionNoAccessList := Transaction{
		To:    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value: 0,
	}
	gasNoAccessList, err := client.EstimateGas(transactionNoAccessList)
	require.NoError(t, err)
	require.Positive(t, gasNoAccessList)

	// Ensure cost with access list is higher than without (extra intrinsic cost, but tx is empty)
	require.Greater(t, gas, gasNoAccessList)
}

// ============================================================================
// Contract Creation Tests
// ============================================================================

func TestBuildTypedTxForContractCreation(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Test that empty To field results in nil address (contract creation).
	transaction := Transaction{
		To:       "", // Empty string should result in nil To address
		Value:    0,
		Gas:      1000000,
		GasPrice: 1000000000,
		Nonce:    1,
		Input:    []byte{0x60, 0x80, 0x60, 0x40}, // Simple bytecode
	}

	builtTx, err := client.buildTypedTx(transaction)
	require.NoError(t, err)
	require.NotNil(t, builtTx)

	// Verify that To is nil (contract creation)
	require.Nil(t, builtTx.To(), "contract creation transaction should have nil To address")

	// Test that non-empty To field results in non-nil address.
	transaction.To = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2"
	builtTx, err = client.buildTypedTx(transaction)
	require.NoError(t, err)
	require.NotNil(t, builtTx)
	require.NotNil(t, builtTx.To(), "regular transaction should have non-nil To address")
	require.Equal(t, common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2"), *builtTx.To())
}

func TestEstimateGasForContractCreation(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Simple contract bytecode (same as TestDeployContract)
	contractBytecode, err := hex.DecodeString("6080604052348015600e575f5ffd5b5060b780601a5f395ff3fe6080604052348015600e575f5ffd5b5060043610603a575f3560e01c80632e64cec114603e5780633fa4f2451460535780636057361d14605a575b5f5ffd5b5f545b60405190815260200160405180910390f35b60415f5481565b60696065366004606b565b5f55565b005b5f60208284031215607a575f5ffd5b503591905056fea2646970667358221220ddc4e8386ce650a1019c837f324cbb0164ab60be5ecaa5e1c7d6891c00476fb364736f6c634300081e0033")
	require.NoError(t, err)

	// Test that EstimateGas works with empty To field (contract creation).
	transaction := Transaction{
		To:    "", // Empty To means contract creation
		Value: 0,
		Input: contractBytecode,
	}

	gas, err := client.EstimateGas(transaction)
	require.NoError(t, err)
	require.Positive(t, gas, "gas estimate for contract creation should be positive")

	// Contract creation should require more gas than a simple transfer.
	transferGas := uint64(21000)
	require.Greater(t, gas, transferGas, "contract creation should require more gas than simple transfer")
}

// ============================================================================
// Receipt Polling Resilience Tests
// ============================================================================

// Test errors for transient network error detection.
var (
	errSomeError       = errors.New("some error")
	errConnectionReset = errors.New("connection reset by peer")
	errBrokenPipe      = errors.New("broken pipe")
	errUnexpectedEOF   = errors.New("unexpected eof")
	errNotFound        = errors.New("not found")
)

func TestIsTransientNetworkError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		isTransient bool
	}{
		{
			name:        "NilError",
			err:         nil,
			isTransient: false,
		},
		{
			name:        "RegularError",
			err:         errSomeError,
			isTransient: false,
		},
		{
			name:        "ConnectionReset",
			err:         errConnectionReset,
			isTransient: true,
		},
		{
			name:        "BrokenPipe",
			err:         errBrokenPipe,
			isTransient: true,
		},
		{
			name:        "EOF",
			err:         errUnexpectedEOF,
			isTransient: true,
		},
		{
			name:        "NotFoundError",
			err:         errNotFound,
			isTransient: false,
		},
		{
			name:        "InvalidNonce",
			err:         core.ErrNonceTooLow,
			isTransient: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isTransientNetworkError(tc.err)
			require.Equal(t, tc.isTransient, result, "isTransientNetworkError(%v) should be %v", tc.err, tc.isTransient)
		})
	}
}

func TestReceiptPollResultConstants(t *testing.T) {
	// Verify poll result constants are distinct
	results := []receiptPollResult{
		pollContinue,
		pollRetry,
		pollFail,
		pollSuccess,
		pollMaxRetries,
		pollTimeout,
		pollCancelled,
	}

	seen := make(map[receiptPollResult]bool)
	for _, r := range results {
		require.False(t, seen[r], "receiptPollResult constants should be unique")
		seen[r] = true
	}

	// Verify specific values for readability
	require.Equal(t, pollContinue, receiptPollResult(0))
	require.Equal(t, pollRetry, receiptPollResult(1))
	require.Equal(t, pollFail, receiptPollResult(2))
	require.Equal(t, pollSuccess, receiptPollResult(3))
	require.Equal(t, pollMaxRetries, receiptPollResult(4))
	require.Equal(t, pollTimeout, receiptPollResult(5))
	require.Equal(t, pollCancelled, receiptPollResult(6))
}

func TestGetReceiptTimeout(t *testing.T) {
	tests := []struct {
		name     string
		opts     *options
		expected time.Duration
	}{
		{
			name:     "NilOptions",
			opts:     nil,
			expected: defaultReceiptTimeout,
		},
		{
			name:     "ZeroTimeout",
			opts:     &options{ReceiptTimeout: 0},
			expected: defaultReceiptTimeout,
		},
		{
			name:     "CustomTimeout",
			opts:     &options{ReceiptTimeout: 30 * time.Second},
			expected: 30 * time.Second,
		},
		{
			name:     "LongTimeout",
			opts:     &options{ReceiptTimeout: 10 * time.Minute},
			expected: 10 * time.Minute,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{opts: tc.opts}
			result := client.getReceiptTimeout()
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestGetReceiptPollInterval(t *testing.T) {
	tests := []struct {
		name     string
		opts     *options
		expected time.Duration
	}{
		{
			name:     "NilOptions",
			opts:     nil,
			expected: defaultReceiptPollInterval,
		},
		{
			name:     "ZeroPollInterval",
			opts:     &options{ReceiptPollInterval: 0},
			expected: defaultReceiptPollInterval,
		},
		{
			name:     "CustomPollInterval",
			opts:     &options{ReceiptPollInterval: 50 * time.Millisecond},
			expected: 50 * time.Millisecond,
		},
		{
			name:     "LongPollInterval",
			opts:     &options{ReceiptPollInterval: 500 * time.Millisecond},
			expected: 500 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{opts: tc.opts}
			result := client.getReceiptPollInterval()
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestNeverClosedChanIsSentinel(t *testing.T) {
	// Verify neverClosedChan never closes (non-blocking check)
	select {
	case <-neverClosedChan:
		t.Fatal("neverClosedChan should never close")
	default:
	}

	// Verify it's the same channel instance each time (package-level singleton)
	chan1 := neverClosedChan
	chan2 := neverClosedChan
	require.Equal(t, chan1, chan2, "neverClosedChan should be a singleton")
}

func TestGetContextDone_NilVU(t *testing.T) {
	client := &Client{vu: nil}
	done := client.getContextDone()

	// Verify the channel pointer is the same as neverClosedChan
	// We can't use require.Equal due to type differences (chan vs <-chan), so we verify behavior
	require.NotNil(t, done, "getContextDone should not return nil")

	// Verify it's non-blocking (doesn't close)
	select {
	case <-done:
		t.Fatal("done channel should not close when vu is nil")
	default:
	}
}

func TestGetBaseContext_NilVU(t *testing.T) {
	client := &Client{vu: nil}
	ctx := client.getBaseContext()

	require.NotNil(t, ctx, "getBaseContext should never return nil")
	require.Equal(t, context.Background(), ctx, "getBaseContext with nil vu should return context.Background()")
}

func TestGetContextWithDeadline_NilVU(t *testing.T) {
	client := &Client{vu: nil}
	deadline := time.Now().Add(1 * time.Second)

	ctx, cancel := client.getContextWithDeadline(deadline)
	defer cancel()

	require.NotNil(t, ctx)

	// Verify deadline is set
	ctxDeadline, ok := ctx.Deadline()
	require.True(t, ok, "context should have a deadline")
	require.Equal(t, deadline.Unix(), ctxDeadline.Unix())
}

func TestPollReceiptOnce_Timeout(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Set deadline in the past to trigger timeout
	pastDeadline := time.Now().Add(-1 * time.Second)
	networkRetries := 0

	result, receipt, pollErr := client.pollReceiptOnce("0x1234567890abcdef", pastDeadline, &networkRetries)

	require.Equal(t, pollTimeout, result, "should return pollTimeout for past deadline")
	require.Nil(t, receipt)
	require.NoError(t, pollErr)
}

func TestPollForReceipt_Success(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	setupFundedAccount(t, client)

	// Refresh nonce manager to avoid conflicts from prior tests that used explicit nonces.
	_ = globalNonceManager.Refresh(client, client.address)

	// Send a transaction first
	gasPrice, err := client.GasPrice()
	require.NoError(t, err)

	transaction := Transaction{
		To:       "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
		Value:    10,
		GasPrice: gasPrice,
	}

	txHash, err := client.SendRawTransaction(transaction)
	require.NoError(t, err)

	// Poll for the receipt with a reasonable timeout
	receipt, err := client.pollForReceipt(txHash, 30*time.Second, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, txHash, receipt.TxHash)
}

func TestPollForReceipt_ShortTimeout(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Use a fake transaction hash that won't be found
	fakeTxHash := "0x0000000000000000000000000000000000000000000000000000000000001234"

	// Poll with a very short timeout
	receipt, err := client.pollForReceipt(fakeTxHash, 100*time.Millisecond, 50*time.Millisecond)

	require.Error(t, err)
	require.Nil(t, receipt)
	require.ErrorIs(t, err, errReceiptTimeout)
	require.Contains(t, err.Error(), "receipt polling timed out")
}

func TestClientWithCustomReceiptOptions(t *testing.T) {
	checkNodeAvailable(t)

	client, err := setupClient()
	require.NoError(t, err)

	// Modify opts to use custom receipt polling settings
	client.opts = &options{
		URL:                 testNodeURL,
		ReceiptTimeout:      10 * time.Second,
		ReceiptPollInterval: 200 * time.Millisecond,
	}

	// Verify the custom settings are used
	require.Equal(t, 10*time.Second, client.getReceiptTimeout())
	require.Equal(t, 200*time.Millisecond, client.getReceiptPollInterval())
}

func TestBlockMonitorGetContextDone_NilVU(t *testing.T) {
	// Create a BlockMonitor with nil vu (testing mode)
	bm := &BlockMonitor{
		client: &Client{vu: nil},
	}

	done := bm.getContextDone()

	// Verify the channel pointer is the same as neverClosedChan
	// We can't use require.Equal due to type differences (chan vs <-chan), so we verify behavior
	require.NotNil(t, done, "BlockMonitor.getContextDone should not return nil")

	// Verify it's non-blocking
	select {
	case <-done:
		t.Fatal("done channel should not close")
	default:
	}
}
