package queue

import (
	"errors"
	"time"

	"go.k6.io/k6/js/common"
)

// Configuration constants.
const (
	// DefaultNumParties is the default number of party queues.
	DefaultNumParties = 7
	// DefaultQueueCapacity is the default capacity per queue.
	DefaultQueueCapacity = 1000
	// MaxParties is the maximum allowed number of parties.
	MaxParties = 32
	// MaxQueueCapacity is the maximum allowed queue capacity.
	MaxQueueCapacity = 100000
)

// Static errors for queue operations.
var (
	errPartiesOutOfRange    = errors.New("parties must be between 1 and 32")
	errCapacityOutOfRange   = errors.New("capacity must be between 1 and 100000")
	errPartyIndexOutOfRange = errors.New("party index out of range")
	errTimeoutNonNegative   = errors.New("timeout must be non-negative")
)

// queueState holds the global queue state.
//
//nolint:gochecknoglobals // Required for inter-VU communication in k6.
var queueState = struct {
	partyQueues   []chan []byte
	numParties    int
	queueCapacity int
	initialized   bool
}{}

// InitializeQueues sets up the party queues with specified configuration.
func (mi *ModuleInstance) InitializeQueues(parties int, capacity int) bool {
	if queueState.initialized {
		return true // Already initialized.
	}

	if parties <= 0 || parties > MaxParties {
		runtime := mi.vu.Runtime()
		common.Throw(runtime, errPartiesOutOfRange)

		return false
	}

	if capacity <= 0 || capacity > MaxQueueCapacity {
		runtime := mi.vu.Runtime()
		common.Throw(runtime, errCapacityOutOfRange)

		return false
	}

	queueState.numParties = parties
	queueState.queueCapacity = capacity
	queueState.partyQueues = make([]chan []byte, queueState.numParties)

	// Initialize all party queues with specified capacity.
	for index := range queueState.numParties {
		queueState.partyQueues[index] = make(chan []byte, queueState.queueCapacity)
	}

	queueState.initialized = true

	return true
}

// Push adds data to the specified party queue (non-blocking).
// Returns true if successful, false if queue is full.
func (mi *ModuleInstance) Push(partyIndex int, data string) bool {
	runtime := mi.vu.Runtime()

	// Ensure queues are initialized with defaults if not already done.
	if !queueState.initialized {
		mi.InitializeQueues(DefaultNumParties, DefaultQueueCapacity)
	}

	// Validate party index.
	if partyIndex < 0 || partyIndex >= queueState.numParties {
		common.Throw(runtime, errPartyIndexOutOfRange)

		return false
	}

	// Convert string to bytes.
	dataBytes := []byte(data)

	// Non-blocking push.
	select {
	case queueState.partyQueues[partyIndex] <- dataBytes:
		return true
	default:
		// Queue is full.
		return false
	}
}

// Pop retrieves data from the specified party queue with timeout.
// Returns the data as string, or null if timeout/empty.
func (mi *ModuleInstance) Pop(partyIndex int, timeoutMs int) *string {
	runtime := mi.vu.Runtime()

	// Ensure queues are initialized with defaults if not already done.
	if !queueState.initialized {
		mi.InitializeQueues(DefaultNumParties, DefaultQueueCapacity)
	}

	// Validate party index.
	if partyIndex < 0 || partyIndex >= queueState.numParties {
		common.Throw(runtime, errPartyIndexOutOfRange)

		return nil
	}

	// Validate timeout.
	if timeoutMs < 0 {
		common.Throw(runtime, errTimeoutNonNegative)

		return nil
	}

	// Handle zero timeout as non-blocking.
	if timeoutMs == 0 {
		select {
		case data := <-queueState.partyQueues[partyIndex]:
			result := string(data)

			return &result
		default:
			return nil
		}
	}

	// Blocking pop with timeout.
	timeout := time.Duration(timeoutMs) * time.Millisecond //nolint:gosec // timeoutMs is validated as non-negative.

	select {
	case data := <-queueState.partyQueues[partyIndex]:
		result := string(data)

		return &result
	case <-time.After(timeout):
		return nil
	}
}

// GetQueueLength returns the current length of the specified party queue.
func (mi *ModuleInstance) GetQueueLength(partyIndex int) int {
	runtime := mi.vu.Runtime()

	// Ensure queues are initialized.
	if !queueState.initialized {
		mi.InitializeQueues(DefaultNumParties, DefaultQueueCapacity)
	}

	// Validate party index.
	if partyIndex < 0 || partyIndex >= queueState.numParties {
		common.Throw(runtime, errPartyIndexOutOfRange)

		return -1
	}

	return len(queueState.partyQueues[partyIndex])
}

// GetQueueCapacity returns the capacity of the party queues.
func (mi *ModuleInstance) GetQueueCapacity() int {
	if !queueState.initialized {
		return DefaultQueueCapacity
	}

	return queueState.queueCapacity
}

// GetNumParties returns the number of configured parties.
func (mi *ModuleInstance) GetNumParties() int {
	if !queueState.initialized {
		return DefaultNumParties
	}

	return queueState.numParties
}

// ClearQueue empties the specified party queue (for testing/cleanup).
func (mi *ModuleInstance) ClearQueue(partyIndex int) int {
	runtime := mi.vu.Runtime()

	// Ensure queues are initialized.
	if !queueState.initialized {
		mi.InitializeQueues(DefaultNumParties, DefaultQueueCapacity)
	}

	// Validate party index.
	if partyIndex < 0 || partyIndex >= queueState.numParties {
		common.Throw(runtime, errPartyIndexOutOfRange)

		return -1
	}

	cleared := 0

	for {
		select {
		case <-queueState.partyQueues[partyIndex]:
			cleared++
		default:
			return cleared
		}
	}
}
