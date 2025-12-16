# Storage Proof Verifier

This module provides on-chain verification of Ethereum storage proofs using
Merkle Patricia Trie proofs.

## Overview

The `StorageProofVerifier` contract allows you to verify that a specific storage
slot in an account had a specific value at a given state root. This is useful
for:

- Cross-chain communication
- State verification without full node access
- Historical state verification

**Important**: The blockhash/state root should be verified against a trusted
registry (e.g., L1 blockhash oracle, cross-chain bridge) before trusting the
proof. This example contract delegates this verification to the caller as the
expected state root is expected to be provided by the caller.

## Usage

### 1. Generate a Storage Proof

Use the Python script to fetch a proof from Sepolia (or any Ethereum network):

```bash
cd contracts

# Basic usage - prove slot 0 of WETH on Sepolia
uv run scripts/generate_storage_proof.py \
    --address 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9 \
    --slot 0 \
    --output proofs/sepolia_storage_proof.json

# Using a config file
uv run scripts/generate_storage_proof.py --config proofs/config.example.json
```

### 2. Run Tests with Gas Reporting

```bash
# Run all storage proof tests
forge test --match-path test/StorageProofVerifier.t.sol -vvv

# With gas report
forge test --match-path test/StorageProofVerifier.t.sol --gas-report
```

## Gas Costs

Typical gas costs for `verifyEthGetProof` verification (from
`forge test --match-path test/StorageProofVerifier.t.sol --gas-report`):

| Contract             | Deployment Cost | Deployment Size |
| -------------------- | --------------: | --------------: |
| StorageProofVerifier |       2,600,529 |          11,910 |

| Function          | Min Gas | Avg Gas |  Median | Max Gas | # Calls |
| ----------------- | ------: | ------: | ------: | ------: | ------: |
| verifyEthGetProof | 769,002 | 769,002 | 769,002 | 769,002 |       1 |

## Security Considerations

1. **State Root Verification**: The contract does NOT verify the state root
   against a blockhash. In production, you must verify the state root is from a
   trusted block using:
   - `blockhash(blockNumber)` for recent blocks (last 256)
   - An L1 blockhash oracle for L2 deployments
   - A blockhash accumulator contract for older blocks

2. **Proof Freshness**: Proofs are only valid for the specific block they were
   generated from.

3. **Reorg Safety**: Consider reorg depth when using storage proofs for critical
   operations.
