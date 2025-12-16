# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Important Rules

- Never keep legacy code in the codebase. If you make changes to functions,
  methods, objects, assume that all the codebase must be transitioned to the new
  layout without any backward compatibility.

### Markdown Writing Rules

When editing this file or other markdown documentation:

- Use proper heading levels (`#`, `##`, `###`, etc.) instead of bold text
  (`**text**`) for section titles
- Bold text followed by a colon and content (e.g., `**Item:** description`) is
  acceptable for labels or key-value pairs
- Standalone bold text that acts as a section divider should be a heading
- Run `trunk check --fix` after editing to catch and fix linting issues

## Project Overview

K6-based blockchain benchmark suite for testing EVM transaction performance with
customizable workloads. Built with TypeScript, Go (xk6 extensions), and Solidity
(Foundry). Metrics are exported to InfluxDB and visualized via Grafana.

## Architecture

### Custom K6 Binary

- **xk6-ethereum**: Go extension providing EVM client operations (transactions,
  contracts, block monitoring). Located in `xk6-ethereum/`, exposes
  `k6/x/ethereum` module to TypeScript scripts
- **xk6-queue**: Go extension for inter-VU communication
- **xk6-output-influxdb**: Extension for InfluxDB metrics output via v2 write
  API (github.com/grafana/xk6-output-influxdb), compatible with InfluxDB v3
- Built via `make build` which runs `xk6 build` with all extensions

#### xk6 Build Process and Dependency Management

**How xk6 builds work:**

1. xk6 creates a **temporary Go module** (new go.mod) in a temp directory
2. Adds k6 and your extensions as dependencies
3. Generates a main.go that imports everything
4. Runs `go build` to create the binary
5. Cleans up the temp directory

##### Critical: Replace Directives Are NOT Transitive

Go modules intentionally **ignore replace directives from dependencies**. Only
the main module's go.mod replace directives are honored. This is documented in
the [Go modules reference](https://go.dev/ref/mod#go-mod-file-replace).

**Why this matters for xk6:**

- xk6 creates a NEW main module (temp go.mod) for each build
- Your `xk6-ethereum` becomes a DEPENDENCY of that temporary main module
- Therefore, any `replace` directives in `xk6-ethereum/go.mod` are IGNORED
- You MUST add replace directives to xk6's main module via the `--replace` flag

##### Example: Using OffchainLabs/go-ethereum fork

This project uses OffchainLabs' fork of go-ethereum instead of the upstream
version. The Makefile includes:

```makefile
--replace github.com/ethereum/go-ethereum=github.com/OffchainLabs/go-ethereum@v0.0.0-20251126100423-ae34a6a9ef5a
```

**Pattern for using any fork with xk6:**

1. Update `xk6-ethereum/go.mod` with your fork (for local development/testing):

   ```go
   require github.com/ethereum/go-ethereum v1.16.7
   replace github.com/ethereum/go-ethereum => github.com/OffchainLabs/go-ethereum@COMMIT_HASH
   ```

2. Add the SAME replace directive to the Makefile xk6 build command:
   ```makefile
   xk6 build \
     --with xk6-ethereum=... \
     --replace github.com/ethereum/go-ethereum=github.com/OffchainLabs/go-ethereum@COMMIT_HASH
   ```

### TypeScript Scripts

The project has two distinct script directories with different runtimes:

**`scripts/`** - k6 benchmark scenarios executed by the custom k6 binary. These
run in k6's Goja JavaScript runtime, which is isolated from Node.js. They cannot
use npm packages or Node.js APIs.

- **arbitrary-execution.ts**: Parameterized workload (storage writes, events,
  calldata size)
- **erc20-rate.ts**: ERC20 transfer throughput
- **eth-rate.ts**: ETH transfers
- **user-decrypt.ts**: FHEVM decryption operations
- **public-decrypt.ts**: FHEVM public decryption
- **allow-public-decrypt.ts**: FHEVM `allowPublicDecrypt` consensus benchmark
  (load/stress, optional batching via Multicall3)

**`bun-scripts/`** - Utility scripts executed with Bun (Node.js compatible).
These can use npm packages (like viem) for tasks that don't require k6's load
testing.

- **refund.ts**: Recovers ETH from test accounts back to the root account

All scripts follow pattern:

1. `setup()`: Deploy contracts, determine gas pricing, optionally deploy
   Multicall3 for batching
2. Main execution function (e.g., `execute()`): Performs transactions using k6
   VUs
3. `monitor()`: Separate scenario that processes block events from WebSocket
   subscription for TPS metrics
4. `handleSummary()`: Export results to JSON

### Helper Modules

Located in `helpers/`:

- **init.ts**: Client initialization, root account resolution (PRIVATE_KEY or
  MNEMONIC), Multicall3 deployment, account funding
- **scenarios.ts**: `getScenarios()` function generates k6 scenario configs.
  Supports two modes:
  - `load` (default): Constant arrival rate for sustained TPS testing
  - `stress`: Ramping arrival rate (30% → 200% of target) to find breaking
    points
- **metrics.ts**: Custom k6 metrics (submit/confirm latency, queue depth, nonce
  management)
- **scheduler.ts**, **thresholds.ts**, **errors.ts**: Additional test
  orchestration utilities

### Smart Contracts

Located in `contracts/src/`:

- **ArbitraryExecution.sol**: Benchmark contract with `runSstore()`,
  `runEvents()`, `runCalldata()` methods for parameterized gas consumption
- **MyToken.sol**: ERC20 implementation for transfer benchmarks
- **Multicall.sol**: Wrapper for Multicall3 (actual implementation via git
  submodule in `lib/multicall3`)
- **mocks/**: FHEVM-related mock contracts (GatewayAddressesMock,
  DecryptionMock)

Dependencies via Foundry submodules:

- `lib/fhevm/`: Zama FHEVM protocol (gateway-contracts, host-contracts)
- `lib/openzeppelin-contracts/` and `lib/openzeppelin-contracts-upgradeable/`

### Data Stack

- **InfluxDB v3 Core**: Metrics storage using SQL query language. The
  xk6-output-influxdb extension writes via the v2 API compatibility endpoint
  (`/api/v2/write`), where `bucket` maps to the database name.
- **Grafana**: Visualization dashboard at
  `http://localhost:3000/d/blockchain_benchmarks_v2/blockchain-benchmarks`.
  Configured with `version: SQL` and Flight SQL (gRPC) for queries.
- Managed via `docker-compose.yml` in project root

## Common Commands

### Setup

```bash
# Install xk6, initialize submodules, install npm deps
make setup

# Build custom k6 binary (auto-runs on benchmark commands if stale)
make build

# Compile Solidity contracts and run setup scripts
make build-contracts
```

### Running Benchmarks

Start local Anvil node first (or configure remote RPC in `.env`):

```bash
anvil --block-time 0.2
```

Run benchmarks:

```bash
# ETH transfers
make run-eth-transfer

# ERC20 transfers
make run-erc20-transfer

# FHEVM decryption benchmarks
make run-user-decrypt
make run-public-decrypt
make run-allow-public-decrypt

# Parameterized arbitrary execution (exactly one parameter required)
make run-arbitrary-execution N_SSTORE=100    # 100 cold storage writes
make run-arbitrary-execution N_EVENTS=500    # Emit 500 bytes of event data
make run-arbitrary-execution CALLDATA_SIZE=1000  # 1000 bytes calldata
```

**Stress testing**: Add `SCENARIO_TYPE=stress` to any benchmark:

```bash
SCENARIO_TYPE=stress make run-erc20-transfer
SCENARIO_TYPE=stress make run-allow-public-decrypt
```

**Batch transactions**: Set `BATCH_SIZE` to use Multicall3:

```bash
BATCH_SIZE=5 make run-arbitrary-execution N_SSTORE=10
BATCH_SIZE=10 make run-allow-public-decrypt
```

### Development

```bash
# Autofix lint & format issues
trunk check --fix
```

### Data Visualization

```bash
# Start InfluxDB + Grafana
docker compose up -d

# Stop and remove volumes
docker compose down -v
```

## Environment Configuration

Copy `.env.example` to `.env` and configure:

- **ETH_RPC_URL**: Blockchain endpoint (default: `http://127.0.0.1:8545`)
- **MNEMONIC** or **PRIVATE_KEY**: Root account for funding test accounts

## Key Implementation Details

### Transaction Batching

When `BATCH_SIZE > 1`:

1. `maybeDeployMulticall3()` deploys Multicall3 contract in setup
2. Scripts use `client.batchCallSync()` to aggregate calls
3. Each batch counts as 1 k6 iteration but contains multiple on-chain
   transactions

### Block Monitoring

All benchmarks run a separate `monitor` scenario:

- Single VU running a WebSocket subscription to `newHeads` events in a loop
  until the scenario duration is reached.
- Uses `client.newBlockMonitor(BATCH_SIZE)` to subscribe and process block
  events
- Calls `processBlockEvent()` to handle incoming block headers and emit metrics
- Emits block metrics as connected samples: `ethereum_block`,
  `ethereum_block_transactions`, `ethereum_gas_used`, `ethereum_uops`, and
  `ethereum_block_time`

### xk6-ethereum Type System

TypeScript types in `xk6-ethereum/types/index.d.ts` define:

- `Client` class methods (gasPrice, sendRawTransaction, deployContract, etc.)
- `Transaction`, `Receipt`, `Log`, `Block` interfaces
- `wallet` module (generateKey, accountsFromMnemonic, accountFromPrivateKey)

Configure TypeScript to resolve:

```json
"paths": {
  "k6/x/ethereum": ["xk6-ethereum/types/index.d.ts"]
}
```

### Go-to-JS Wrapper Types (jstypes.go)

**Problem**: go-ethereum types use `json` struct tags (e.g.,
`json:"contractAddress"`), but k6's sobek runtime uses `js` tags for field name
mapping. Without `js` tags, Go's PascalCase field names get converted to
snake_case in JavaScript (e.g., `ContractAddress` → `contract_address`),
breaking the expected camelCase API.

**Solution**: `xk6-ethereum/jstypes.go` defines wrapper types that mirror
go-ethereum types but with proper `js` tags:

- `Receipt` - wraps `types.Receipt` with `js:"transactionHash"`,
  `js:"contractAddress"`, etc.
- `Log` - wraps `types.Log` with camelCase js tags
- `Block` - wraps `types.Block` (extracts method values into struct fields)
- `BlockTransaction` - wraps transaction data within blocks

Conversion functions (`NewReceipt`, `NewLog`, `NewBlock`) handle the
transformation from go-ethereum types to wrapper types. All public methods
returning these types convert before returning to JavaScript.

**When adding new go-ethereum types to the JS API**: Always create a wrapper
type in `jstypes.go` with explicit `js` tags for each field, and convert using a
`New*` constructor before returning to JavaScript.

### Foundry Contract Setup

Before first run of contract-dependent benchmarks:

```bash
cd contracts
bash scripts/setup-gateway-addresses.sh  # Configures FHEVM gateway mocks
forge build
```

Outputs: `contracts/out/<ContractName>.sol/<ContractName>.{abi.json,bin}`

### Test Modes

- **Load testing** (default): Validates sustained TPS under fixed rate
- **Stress testing** (`SCENARIO_TYPE=stress`): Identifies max capacity via
  ramping load; auto-aborts if p95 latency > 2.5s

## Common Pitfalls

1. **"Invalid JSON RPC response"**: Ensure Anvil is running or ETH_RPC_URL
   points to valid endpoint

2. **Fork not being used in xk6 binary**: If you add a `replace` directive to
   `xk6-ethereum/go.mod` but it's not reflected at runtime, remember that Go
   modules ignore replace directives from dependencies. You MUST add the
   `--replace` flag to the xk6 build command in the Makefile. See "xk6 Build
   Process and Dependency Management" section for details.

3. **go.work.sum out of sync**: After updating go.mod files or replace
   directives, run `go work sync` from the project root to update workspace
   checksums
