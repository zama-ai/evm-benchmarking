package ethereum

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

// Anvil default account 0 address.
const testAccountAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

// ============================================================================
// NonceManager Unit Tests
// ============================================================================

func TestNonceManagerAcquireInitializesAndIncrements(t *testing.T) {
	server := newNonceRPCServer(t, []nonceResponder{successNonce("0x5")})
	t.Cleanup(server.Close)

	client := server.Client(t)
	manager := &NonceManager{}
	addr := common.HexToAddress(testAccountAddress)

	n1, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(5), n1)

	n2, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(6), n2)

	require.Equal(t, 1, server.CallCount(), "nonce should be fetched once then cached")
}

func TestNonceManagerRefreshSuccess(t *testing.T) {
	server := newNonceRPCServer(t, []nonceResponder{successNonce("0x5"), successNonce("0xa")})
	t.Cleanup(server.Close)

	client := server.Client(t)
	manager := &NonceManager{}
	addr := common.HexToAddress(testAccountAddress)

	n1, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(5), n1)

	require.NoError(t, manager.Refresh(client, addr))

	n2, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(10), n2, "refresh should reset next nonce")

	n3, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(11), n3)

	require.Equal(t, 2, server.CallCount(), "init + refresh should each call node once")
}

func TestNonceManagerRefreshFailureResetsInitialization(t *testing.T) {
	server := newNonceRPCServer(t, []nonceResponder{
		successNonce("0x2"),
		errorNonce("boom"),
		successNonce("0x7"),
	})
	t.Cleanup(server.Close)

	client := server.Client(t)
	manager := &NonceManager{}
	addr := common.HexToAddress(testAccountAddress)

	n1, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(2), n1)

	err = manager.Refresh(client, addr)
	require.Error(t, err, "refresh should surface RPC error")

	// After a failed refresh, the manager should mark the entry uninitialized and
	// re-fetch from the node on the next Acquire.
	n2, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(7), n2)

	n3, err := manager.Acquire(client, addr)
	require.NoError(t, err)
	require.Equal(t, uint64(8), n3)

	require.Equal(t, 3, server.CallCount(), "init + failed refresh + reinitialize after failure")
}

// nonceResponder describes a single queued JSON-RPC reply for eth_getTransactionCount.
type nonceResponder struct {
	result string
	errMsg string
}

// successNonce returns a responder that yields a successful nonce hex value.
func successNonce(hexNonce string) nonceResponder {
	return nonceResponder{result: hexNonce}
}

// errorNonce returns a responder that yields an error response with the given message.
func errorNonce(msg string) nonceResponder {
	return nonceResponder{errMsg: msg}
}

// nonceRPCServer is a tiny deterministic JSON-RPC stub for nonce manager tests.
// It queues eth_getTransactionCount responses and records call counts.
type nonceRPCServer struct {
	t          *testing.T
	server     *httptest.Server
	responders []nonceResponder
	calls      int
}

func newNonceRPCServer(t *testing.T, responders []nonceResponder) *nonceRPCServer {
	t.Helper()

	serverStub := &nonceRPCServer{t: t, responders: responders}

	serverStub.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		_ = request.Body.Close()

		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}

		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}

		writer.Header().Set("Content-Type", "application/json")

		// Support chainId requests for completeness.
		if req.Method == "eth_chainId" {
			_, _ = fmt.Fprintf(writer, `{"jsonrpc":"2.0","id":%v,"result":"0x1"}`, req.ID)

			return
		}

		if req.Method != "eth_getTransactionCount" {
			t.Fatalf("unexpected method %s", req.Method)

			return
		}

		idx := serverStub.calls
		if idx >= len(serverStub.responders) {
			idx = len(serverStub.responders) - 1
		}

		resp := serverStub.responders[idx]
		serverStub.calls++

		if resp.errMsg != "" {
			_, _ = fmt.Fprintf(writer, `{"jsonrpc":"2.0","id":%v,"error":{"code":-32000,"message":"%s"}}`, req.ID, resp.errMsg)

			return
		}

		_, _ = fmt.Fprintf(writer, `{"jsonrpc":"2.0","id":%v,"result":"%s"}`, req.ID, resp.result)
	}))

	return serverStub
}

func (s *nonceRPCServer) Client(t *testing.T) *Client {
	t.Helper()

	rpcClient, err := rpc.Dial(s.server.URL)
	require.NoError(t, err)

	ethClient := ethclient.NewClient(rpcClient)

	return &Client{
		client:    ethClient,
		rpcClient: rpcClient,
		opts: &options{
			URL: s.server.URL,
		},
	}
}

func (s *nonceRPCServer) Close() {
	s.server.Close()
}

func (s *nonceRPCServer) CallCount() int {
	return s.calls
}
