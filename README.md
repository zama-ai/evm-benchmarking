# EVM Benchmarking

Load testing framework for EVM-based blockchains using k6 with custom Ethereum
extensions. Measures transaction throughput, latency, and time-to-mine metrics.

## Quick Start

```bash
# Install dependencies
make setup

# Configure environment
cp .env.example .env

# Start a local node (or use a remote RPC)
anvil --block-time 0.2 --gas-price 1

# Run a benchmark
make run-erc20-transfer
```

## Prerequisites

- **Go 1.24+** - For building the k6 extension
- **Foundry** - For smart contract compilation and local testing with anvil.
- **Bun** - For utility scripts that support node.js packages.

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup --install v1.5.0

curl -fsSL https://bun.com/install | bash
bun install
```

## Setup

```bash
make setup
```

This initializes git submodules, installs the xk6 CLI, and prepares
dependencies.

## Project Structure

```text
scripts/          # k6 benchmark scenarios (Goja runtime)
bun-scripts/      # Utility scripts, supports node.js packages (Bun runtime)
xk6-ethereum/     # k6 Ethereum extension (Go)
contracts/        # Solidity contracts to benchmark
helpers/          # Shared k6 scenario utilities
```

### Scripts vs Bun-Scripts

The project contains two types of TypeScript files with different runtimes:

**`scripts/`** - k6 benchmark scenarios executed by the custom k6 binary. These
run in k6's Goja JavaScript runtime, which is isolated from Node.js. They cannot
use npm packages or Node.js APIs. Instead, they use k6's built-in modules and
the xk6 extensions, like our xk6-ethereum extension.

**`bun-scripts/`** - Utility scripts executed with Bun (Node.js compatible).
These can use any npm package (like viem) and are used for tasks that don't
require k6's load testing capabilities, such as refunding test accounts,
preparing the environment before running a benchmark, etc.

## Running Benchmarks

### Available Scenarios

```bash
make run-eth-transfer           # Native ETH transfers
make run-erc20-transfer         # ERC20 token transfers
make run-arbitrary-execution    # Configurable contract execution
make run-user-decrypt           # FHE user decryption
make run-public-decrypt         # FHE public decryption
make run-allow-public-decrypt   # FHE allowPublicDecrypt
```

### Configuration

Benchmarks are configured via environment variables:

| Variable        | Default | Description                             |
| --------------- | ------- | --------------------------------------- |
| `RATE`          | 500     | Target transactions per second          |
| `DURATION`      | 120     | Test duration in seconds                |
| `BATCH_SIZE`    | 1       | Transactions per iteration (Multicall3) |
| `SCENARIO_TYPE` | stress  | `load` (constant) or `stress` (ramping) |

```bash
RATE=100 DURATION=60 SCENARIO_TYPE=load make run-erc20-transfer
```

### Load vs Stress Testing

**Load testing** (`SCENARIO_TYPE=load`) maintains a constant transaction rate
throughout the test. Use this to validate that a system handles a specific
sustained load.

**Stress testing** (`SCENARIO_TYPE=stress`) ramps from 30% to 200% of the target
rate. Use this to find the system's breaking point. Tests abort if p95 latency
exceeds 2.5 seconds.

## Visualization

Start the monitoring stack for real-time metrics:

```bash
docker compose up -d
```

Access Grafana at [http://localhost:3000](http://localhost:3000). Metrics are
exported to InfluxDB automatically during benchmark runs.

## Writing Custom Benchmarks

Create a new file in `scripts/`:

```typescript
import { initializeClient } from "../helpers/init.ts";
import { monitoringLoop } from "../helpers/monitoring.ts";
import { getScenarios } from "../helpers/scenarios.ts";

export const options = getScenarios("my-benchmark");

const client = initializeClient();

export function setup() {
  // Runs once before VUs start
  return { gasPrice: client.gasPrice() };
}

export default function (data: { gasPrice: number }) {
  // Each VU iteration executes this function
  const receipt = client.sendTransactionSync({
    to: "0x...",
    value: 1000,
    gasPrice: data.gasPrice,
  });
}

export function monitor() {
  // Block monitoring for TPS metrics
  monitoringLoop();
}
```

Add a Makefile target:

```makefile
.PHONY: run-my-benchmark
run-my-benchmark: build
    $(K6_OUTPUT) run --out xk6-influxdb scripts/my-benchmark.ts
```

See [xk6-ethereum/README.md](xk6-ethereum/README.md) for the full API reference.

## Utility Scripts

Utility scripts run with Bun and can use npm packages:

```bash
make refund  # Recover ETH from test accounts back to the root account
```

## Cleanup

```bash
docker compose down     # Stop containers
docker compose down -v  # Stop and remove data
```
