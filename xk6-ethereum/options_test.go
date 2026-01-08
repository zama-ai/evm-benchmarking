package ethereum

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewOptionsFrom_UnknownField(t *testing.T) {
	_, err := newOptionsFrom(map[string]any{
		"url":     "http://localhost:8545",
		"unknown": 1,
	})
	require.Error(t, err)
}

func TestNewOptionsFrom_DurationConversion(t *testing.T) {
	opts, err := newOptionsFrom(map[string]any{
		"url":                 "http://localhost:8545",
		"receiptTimeout":      500,  // treated as ms because < 1s when decoded as ns
		"receiptPollInterval": 2500, // 2.5s in ms
	})
	require.NoError(t, err)
	require.Equal(t, 500*time.Millisecond, opts.ReceiptTimeout)
	require.Equal(t, 2500*time.Millisecond, opts.ReceiptPollInterval)

	opts, err = newOptionsFrom(map[string]any{
		"url":            "http://localhost:8545",
		"receiptTimeout": int64(2 * time.Second), // already nanoseconds; should remain 2s
	})
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, opts.ReceiptTimeout)
}
