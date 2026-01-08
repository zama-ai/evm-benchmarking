package ethereum

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// Static errors for nonce manager operations.
var errInvalidNonceEntryType = errors.New("invalid nonce entry type")

// NonceManager coordinates nonces across all VUs and Clients for the same
// (rpc URL, account) pair to avoid concurrent nonce reuse.
//
// It's a simple process-wide singleton keyed by url+address with per-entry
// locking and lazy initialization from the node's pending nonce.
type NonceManager struct {
	entries sync.Map // key -> *nonceEntry
}

type nonceEntry struct {
	mu          sync.Mutex
	initialized bool
	next        uint64
}

//nolint:gochecknoglobals // Process-wide singleton for nonce coordination across VUs.
var globalNonceManager = &NonceManager{}

func nonceKey(url string, addr common.Address) string {
	// Include URL and address to avoid collisions across endpoints.
	return fmt.Sprintf("%s|%s", url, addr.Hex())
}

// Acquire reserves and returns the next nonce for the given account.
// It initializes from the node's pending nonce on first use.
func (manager *NonceManager) Acquire(client *Client, addr common.Address) (uint64, error) {
	key := nonceKey(client.opts.URL, addr)
	val, _ := manager.entries.LoadOrStore(key, &nonceEntry{})

	entry, ok := val.(*nonceEntry)
	if !ok {
		return 0, errInvalidNonceEntryType
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if !entry.initialized {
		nonce, err := client.client.PendingNonceAt(client.getBaseContext(), addr)
		if err != nil {
			return 0, fmt.Errorf("failed to get nonce: %w", err)
		}

		entry.next = nonce
		entry.initialized = true
	}

	nonce := entry.next
	entry.next++

	return nonce, nil
}

// Refresh resets the entry from the node state so the next Acquire returns a
// fresh, conflict-free nonce.
func (manager *NonceManager) Refresh(client *Client, addr common.Address) error {
	key := nonceKey(client.opts.URL, addr)
	val, _ := manager.entries.LoadOrStore(key, &nonceEntry{})

	entry, ok := val.(*nonceEntry)
	if !ok {
		return errInvalidNonceEntryType
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	nonce, err := client.client.PendingNonceAt(client.getBaseContext(), addr)
	if err != nil {
		// Mark uninitialized so a subsequent Acquire can retry initialization.
		entry.initialized = false
		entry.next = 0

		return fmt.Errorf("failed to get nonce: %w", err)
	}

	entry.next = nonce
	entry.initialized = true

	return nil
}
