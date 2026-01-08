# xk6-ethereum

A k6 extension for interacting with EVM-based blockchains. Provides Ethereum RPC
client capabilities and wallet utilities for load testing blockchain
applications.

## Installation

Build a custom k6 binary with this extension using
[xk6](https://github.com/grafana/xk6):

```bash
go install go.k6.io/xk6/cmd/xk6@latest

xk6 build --with xk6-ethereum=/path/to/xk6-ethereum
```

This produces a `k6` binary with the extension included.

## Usage

### Creating a Client

```typescript
import eth from "k6/x/ethereum";

const client = new eth.Client({
  url: "http://127.0.0.1:8545",
  privateKey: "your-private-key-hex", // optional, required for signing transactions
  receiptTimeout: 300000, // optional, milliseconds (default 5 minutes)
  receiptPollInterval: 100, // optional, milliseconds (default 100ms)
});
```

#### Client Options

- `url` (string, required): Ethereum RPC endpoint.
- `privateKey` (string, optional): Hex private key for signing (with or without
  `0x`). Required for transaction signing methods.
- `receiptTimeout` (number, optional): Max time to wait for receipt polling, in
  milliseconds. Defaults to `300000` (5 minutes).
- `receiptPollInterval` (number, optional): Interval between receipt polls, in
  milliseconds. Defaults to `100`.

If `privateKey` is omitted, the client can still perform read-only calls and
monitoring, but signing methods will throw unless you call `setPrivateKey()`.

### Sending Transactions

The extension provides several methods depending on your needs:

| Method                            | Waits for Receipt | Best For                                |
| --------------------------------- | ----------------- | --------------------------------------- |
| `sendTransaction(tx)`             | No                | Fire-and-forget scenarios               |
| `sendTransactionSync(tx)`         | Yes               | Nodes with `eth_sendRawTransactionSync` |
| `sendTransactionAndWaitReceipt()` | Yes (polling)     | Standard nodes                          |

```typescript
// Fire-and-forget
const hash = client.sendTransaction({ to: address, value: 1000 });

// Wait for receipt (sync RPC)
const receipt = client.sendTransactionSync({ to: address, value: 1000 });

// Wait for receipt (polling)
const receipt = client.sendTransactionAndWaitReceipt({
  to: address,
  value: 1000,
});
```

### Contract Interactions

```typescript
const contract = client.newContract(contractAddress, abiJson);

// Read-only call
const balance = contract.call("balanceOf", address);

// Write transaction (fire-and-forget)
const hash = contract.txn("transfer", { gasPrice: 1000000 }, recipient, amount);

// Write transaction (wait for receipt)
const receipt = contract.txnSync(
  "transfer",
  { gasPrice: 1000000 },
  recipient,
  amount,
);

// Encode calldata without sending
const calldata = contract.encodeABI("transfer", recipient, amount);
```

### Batch Operations (Multicall3)

```typescript
import type { Call3 } from "k6/x/ethereum";

const calls: Call3[] = [
  {
    target: tokenAddr,
    allowFailure: false,
    calldata: contract.encodeABI("transfer", addr1, 100n),
  },
  {
    target: tokenAddr,
    allowFailure: false,
    calldata: contract.encodeABI("transfer", addr2, 100n),
  },
];

const receipt = client.batchCallSync(multicallAddress, calls, { gasPrice });
```

### Wallet Utilities

```typescript
import * as wallet from "k6/x/ethereum/wallet";

// Generate a new key pair
const account = wallet.generateKey();

// Derive accounts from mnemonic (BIP-44 path: m/44'/60'/0'/0/i)
const accounts = wallet.accountsFromMnemonic(
  "test test test test test test test test test test test junk",
  10, // count
);

// Import from private key
const account = wallet.accountFromPrivateKey("0x...");
```

## Metrics

The extension collects and exports the following metrics to InfluxDB (via
xk6-output-influxdb or compatible outputs):

| Metric                        | Type    | Description                                              |
| ----------------------------- | ------- | -------------------------------------------------------- |
| `ethereum_block_count`        | Counter | Count of blocks observed                                 |
| `ethereum_block_number`       | Trend   | Current block number observed during monitoring          |
| `ethereum_block_transactions` | Trend   | User transaction count per block                         |
| `ethereum_uops`               | Trend   | User ops per block (batchSize \* tx count)               |
| `ethereum_gas_used`           | Trend   | Gas used per block                                       |
| `ethereum_block_time`         | Trend   | Block time delta (ms)                                    |
| `ethereum_time_to_mine`       | Trend   | Time from transaction submission to block inclusion (ms) |
| `ethereum_req_duration`       | Trend   | Duration of individual RPC calls (ms)                    |
| `ethereum_errors`             | Counter | RPC errors by method                                     |

### Block Monitoring

To collect block-level metrics (for example `ethereum_block_count`,
`ethereum_block_number`, `ethereum_block_transactions`), use the block monitor
in a dedicated scenario:

```typescript
const monitor = client.newBlockMonitor(10); // batch size

export function monitorBlocks() {
  monitor.processBlockEvent(); // Processes new blocks and emits metrics
}
```

The monitor subscribes to new block headers and calculates TPS based on
transaction counts per block.

Note: `newBlockMonitor()` will throw if the WebSocket connection or subscription
fails.

## API Reference

See [types/index.d.ts](types/index.d.ts) for the complete TypeScript type
definitions covering all client methods, transaction types, and wallet
utilities.

## License

MIT License. Portions derived from
[xk6-ethereum](https://github.com/distribworks/xk6-ethereum).
