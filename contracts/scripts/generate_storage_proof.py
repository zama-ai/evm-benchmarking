#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "web3>=7.0.0",
#     "python-dotenv>=1.0.0",
# ]
# ///
"""
Generate storage proof for fhevm ACL persistedAllowedPairs mapping on Sepolia.

This script generates a storage proof for the ACL contract's persistedAllowedPairs[handle][address]
storage slot, which tracks which addresses have permission to access specific ciphertext handles.

Storage slot calculation:
    ACLStorageLocation = 0xa688f31953c2015baaf8c0a488ee1ee22eb0e05273cc1fd31ea4cbee42febc00
    persistedAllowedPairs is a mapping(uint256 handle => mapping(address address => bool))

    For nested mappings, the slot is calculated as:
        inner_slot = keccak256(abi.encode(handle, base_slot))
        final_slot = keccak256(abi.encode(address, inner_slot))

Usage:
    # Generate proof for a specific handle and address:
    uv run scripts/generate_storage_proof.py --handle 0x123... --address 0xabc...

    # With specific block:
    uv run scripts/generate_storage_proof.py --handle 0x123... --address 0xabc... --block 1234567

    # Custom ACL address:
    uv run scripts/generate_storage_proof.py --handle 0x123... --address 0xabc... --address 0x...
"""

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

# Default ACL contract address on Sepolia
DEFAULT_ACL_ADDRESS = "0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D"

# ACL storage location from EIP-7201 namespaced storage
# keccak256(abi.encode(uint256(keccak256("fhevm.storage.ACL")) - 1)) & ~bytes32(uint256(0xff))
ACL_STORAGE_LOCATION = (
    0xA688F31953C2015BAAF8C0A488EE1EE22EB0E05273CC1FD31EA4CBEE42FEBC00
)

# Offset of persistedAllowedPairs within ACLStorage struct (first field = 0)
PERSISTED_ALLOWED_PAIRS_OFFSET = 0


def calculate_nested_mapping_slot(handle: int, address: str, base_slot: int) -> int:
    """
    Calculate storage slot for persistedAllowedPairs[handle][address].

    For a nested mapping mapping(uint256 => mapping(address => bool)):
        inner_slot = keccak256(abi.encode(handle, base_slot))
        final_slot = keccak256(abi.encode(address, inner_slot))

    Args:
        handle: The ciphertext handle (uint256)
        address: The address address
        base_slot: Base slot of the mapping

    Returns:
        The storage slot as an integer
    """
    # Calculate inner mapping slot: keccak256(abi.encode(handle, base_slot))
    inner_slot_data = handle.to_bytes(32, "big") + base_slot.to_bytes(32, "big")
    inner_slot = int.from_bytes(Web3.keccak(inner_slot_data), "big")

    # Calculate final slot: keccak256(abi.encode(address_as_uint256, inner_slot))
    address_int = int(address, 16)
    final_slot_data = address_int.to_bytes(32, "big") + inner_slot.to_bytes(32, "big")
    final_slot = int.from_bytes(Web3.keccak(final_slot_data), "big")

    return final_slot


def get_storage_proof(
    w3: Web3,
    address: str,
    slot: int,
    block_identifier: str | int = "latest",
) -> dict:
    """Fetch storage proof using eth_getProof RPC call."""
    # Convert slot to hex format (32 bytes)
    slot_hex = hex(slot)

    # Make eth_getProof call
    proof_response = w3.eth.get_proof(
        Web3.to_checksum_address(address),
        [slot_hex],
        block_identifier=block_identifier,
    )

    return proof_response


def format_proof_for_solidity(
    proof_response: dict, block: dict, handle: int, address: str
) -> dict:
    """Format the proof response for use in Solidity tests."""
    # Extract account proof (list of RLP-encoded nodes)
    account_proof = ["0x" + node.hex() for node in proof_response["accountProof"]]

    # Extract storage proof for the first (and only) storage key
    storage_proof_data = proof_response["storageProof"][0]
    storage_proof = ["0x" + node.hex() for node in storage_proof_data["proof"]]

    return {
        "metadata": {
            "network": "sepolia",
            "blockNumber": block["number"],
            "blockHash": "0x" + block["hash"].hex(),
            "timestamp": block["timestamp"],
            "handle": hex(handle),
            "address": address,
        },
        "params": {
            "stateRoot": "0x" + block["stateRoot"].hex(),
            "account": proof_response["address"],
            "slot": "0x" + storage_proof_data["key"].hex(),
            "expectedValue": "0x" + storage_proof_data["value"].hex().zfill(64),
        },
        "accountProof": account_proof,
        "storageProof": storage_proof,
        "accountData": {
            "nonce": proof_response["nonce"],
            "balance": hex(proof_response["balance"]),
            "storageHash": "0x" + proof_response["storageHash"].hex(),
            "codeHash": "0x" + proof_response["codeHash"].hex(),
        },
    }


def main():
    """Main entry point."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Generate storage proof for ACL persistedAllowedPairs mapping"
    )
    parser.add_argument(
        "--handle",
        "-H",
        required=True,
        type=lambda x: int(x, 0),  # Supports hex (0x...) and decimal
        help="Ciphertext handle (uint256, decimal or hex with 0x prefix)",
    )
    parser.add_argument(
        "--address",
        "-d",
        required=True,
        help="address address (0x...)",
    )
    parser.add_argument(
        "--address",
        "-a",
        default=DEFAULT_ACL_ADDRESS,
        help=f"ACL contract address (default: {DEFAULT_ACL_ADDRESS})",
    )
    parser.add_argument(
        "--block",
        "-b",
        default="latest",
        help="Block number or 'latest' (default: latest)",
    )
    parser.add_argument(
        "--rpc-url",
        "-r",
        default=os.getenv(
            "SEPOLIA_RPC_URL", "https://ethereum-sepolia-rpc.publicnode.com"
        ),
        help="Sepolia RPC URL (default: from SEPOLIA_RPC_URL env or public node)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="proofs/sepolia_storage_proof.json",
        help="Output file path (default: proofs/sepolia_storage_proof.json)",
    )
    parser.add_argument(
        "--mapping-offset",
        "-m",
        type=int,
        default=PERSISTED_ALLOWED_PAIRS_OFFSET,
        help=f"Offset of persistedAllowedPairs within ACLStorage struct (default: {PERSISTED_ALLOWED_PAIRS_OFFSET})",
    )

    args = parser.parse_args()

    # Validate address address
    if not Web3.is_address(args.address):
        print(f"Error: Invalid address address: {args.address}")
        sys.exit(1)

    # Convert block to int if it's a number string
    block = args.block
    if block != "latest":
        block = int(block, 0) if isinstance(block, str) else block

    # Calculate the storage slot
    base_slot = ACL_STORAGE_LOCATION + args.mapping_offset
    storage_slot = calculate_nested_mapping_slot(args.handle, args.address, base_slot)

    print(f"Connecting to Sepolia RPC: {args.rpc_url}")
    w3 = Web3(Web3.HTTPProvider(args.rpc_url))

    if not w3.is_connected():
        print("Error: Could not connect to RPC")
        sys.exit(1)

    print("\nACL Storage Proof Generator")
    print("=" * 50)
    print(f"ACL Address: {args.address}")
    print(f"Handle: {hex(args.handle)}")
    print(f"address: {args.address}")
    print(f"Block: {block}")
    print("\nStorage slot calculation:")
    print(f"  ACL Storage Location: 0x{ACL_STORAGE_LOCATION:064x}")
    print(f"  Mapping offset: {args.mapping_offset}")
    print(f"  Base slot: 0x{base_slot:064x}")
    print(f"  Final slot: 0x{storage_slot:064x}")

    # Get the proof
    proof_response = get_storage_proof(w3, args.address, storage_slot, block)

    # Get block data for state root
    block_data = w3.eth.get_block(block)

    # Format for Solidity
    formatted_proof = format_proof_for_solidity(
        proof_response, block_data, args.handle, args.address
    )

    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write to file
    with open(output_path, "w") as f:
        json.dump(formatted_proof, f, indent=2)

    print("\n" + "=" * 50)
    print(f"Proof written to: {output_path}")
    print(f"\nStorage value: {formatted_proof['params']['expectedValue']}")
    print(f"State root: {formatted_proof['params']['stateRoot']}")
    print(f"Account proof nodes: {len(formatted_proof['accountProof'])}")
    print(f"Storage proof nodes: {len(formatted_proof['storageProof'])}")


if __name__ == "__main__":
    main()
