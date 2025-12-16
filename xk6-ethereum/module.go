package ethereum

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/grafana/sobek"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
	"go.k6.io/k6/metrics"
)

// Static errors for module operations.
var (
	errUnableToParseOptions = errors.New("unable to parse options object")
	errPrivateKeyRequired   = errors.New("Client must be initialized with a private key")
	errURLRequired          = errors.New("Client must be initialized with a URL")
)

type ethMetrics struct {
	RequestDuration   *metrics.Metric
	TimeToMine        *metrics.Metric
	BlockCount        *metrics.Metric
	BlockNumber       *metrics.Metric
	GasUsed           *metrics.Metric
	BlockTransactions *metrics.Metric
	BlockUserOps      *metrics.Metric
	BlockTime         *metrics.Metric
	Errors            *metrics.Metric
}

func init() { //nolint:gochecknoinits // Required for k6 module registration.
	modules.Register("k6/x/ethereum", &EthRoot{})
}

// EthRoot is the root module.
type EthRoot struct{}

// NewModuleInstance implements the modules.Module interface returning a new instance for each VU.
func (*EthRoot) NewModuleInstance(vu modules.VU) modules.Instance {
	return &ModuleInstance{
		vu:         vu,
		ethMetrics: registerMetrics(vu),
	}
}

// ModuleInstance represents a k6 module instance for the Ethereum extension.
type ModuleInstance struct {
	vu         modules.VU
	ethMetrics ethMetrics
}

// Exports implements the modules.Instance interface and returns the exported types for the JS module.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Named: map[string]any{
		"Client": mi.NewClient,
	}}
}

// NewClient creates a new Ethereum client instance.
func (mi *ModuleInstance) NewClient(call sobek.ConstructorCall) *sobek.Object {
	runtime := mi.vu.Runtime()

	var optionsArg map[string]any

	err := runtime.ExportTo(call.Arguments[0], &optionsArg)
	if err != nil {
		common.Throw(runtime, errUnableToParseOptions)
	}

	opts, err := newOptionsFrom(optionsArg)
	if err != nil {
		common.Throw(runtime, fmt.Errorf("invalid options; reason: %w", err))
	}

	if opts.PrivateKey == "" {
		common.Throw(runtime, errPrivateKeyRequired)
	}

	if opts.URL == "" {
		common.Throw(runtime, errURLRequired)
	}

	// Remove 0x prefix if present.
	privateKeyHex := opts.PrivateKey
	if len(privateKeyHex) > 2 && privateKeyHex[:2] == "0x" {
		privateKeyHex = privateKeyHex[2:]
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		common.Throw(runtime, fmt.Errorf("invalid options; reason: %w", err))
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		common.Throw(runtime, fmt.Errorf("invalid options; reason: %w", err))
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Create both ethclient and raw rpc client.
	sharedTransport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 2000,
		MaxConnsPerHost:     2000,
		IdleConnTimeout:     90 * time.Second,
	}

	rpcClient, err := rpc.DialOptions(context.Background(), opts.URL, rpc.WithHTTPClient(&http.Client{
		Transport: sharedTransport,
	}))
	if err != nil {
		common.Throw(runtime, fmt.Errorf("invalid options; reason: %w", err))
	}

	ethClient := ethclient.NewClient(rpcClient)

	chainID, err := ethClient.ChainID(context.Background())
	if err != nil {
		common.Throw(runtime, fmt.Errorf("invalid options; reason: %w", err))
	}

	client := &Client{
		vu:         mi.vu,
		metrics:    mi.ethMetrics,
		client:     ethClient,
		rpcClient:  rpcClient,
		privateKey: privateKey,
		address:    address,
		chainID:    chainID,
		opts:       opts,
	}

	return runtime.ToValue(client).ToObject(runtime)
}

func registerMetrics(vu modules.VU) ethMetrics {
	registry := vu.InitEnv().Registry

	return ethMetrics{
		RequestDuration:   registry.MustNewMetric("ethereum_req_duration", metrics.Trend, metrics.Time),
		TimeToMine:        registry.MustNewMetric("ethereum_time_to_mine", metrics.Trend, metrics.Time),
		BlockCount:        registry.MustNewMetric("ethereum_block_count", metrics.Counter, metrics.Default),
		BlockNumber:       registry.MustNewMetric("ethereum_block_number", metrics.Trend, metrics.Default),
		GasUsed:           registry.MustNewMetric("ethereum_gas_used", metrics.Trend, metrics.Default),
		BlockTransactions: registry.MustNewMetric("ethereum_block_transactions", metrics.Trend, metrics.Default),
		BlockUserOps:      registry.MustNewMetric("ethereum_uops", metrics.Trend, metrics.Default),
		BlockTime:         registry.MustNewMetric("ethereum_block_time", metrics.Trend, metrics.Time),
		Errors:            registry.MustNewMetric("ethereum_errors", metrics.Counter, metrics.Default),
	}
}

// options defines configuration options for the client.
type options struct {
	URL        string `js:"url"`
	PrivateKey string `js:"privateKey"`
}

// newOptionsFrom validates and instantiates an options struct from its map representation
// as obtained by calling a Goja's Runtime.ExportTo.
func newOptionsFrom(argument map[string]any) (*options, error) {
	jsonStr, err := json.Marshal(argument)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize options to JSON: %w", err)
	}

	// Instantiate a JSON decoder which will error on unknown
	// fields. As a result, if the input map contains an unknown
	// option, this function will produce an error.
	decoder := json.NewDecoder(bytes.NewReader(jsonStr))
	decoder.DisallowUnknownFields()

	var opts options

	err = decoder.Decode(&opts)
	if err != nil {
		return nil, fmt.Errorf("unable to decode options: %w", err)
	}

	return &opts, nil
}
