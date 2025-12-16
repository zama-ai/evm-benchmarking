/* solhint-disable no-inline-assembly */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleTrie} from "@optimism-bedrock/libraries/trie/MerkleTrie.sol";
import {RLPReader} from "@optimism-bedrock/libraries/rlp/RLPReader.sol";

/// @title StorageProofVerifier
/// @notice Verifies Ethereum storage proofs against a given state root.
/// @dev This contract demonstrates storage proof verification.
///      In production, the blockhash should be checked against a trusted registry
///      (e.g., L1 block hash oracle, cross-chain bridge, or blockhash accumulator).
contract StorageProofVerifier {
    /// @notice Account RLP structure index for storage root
    uint256 private constant ACCOUNT_STORAGE_ROOT_INDEX = 2;

    error InvalidAccountRLP();
    error InvalidStorageValue();

    /// @notice Result of a storage proof verification
    struct StorageProofResult {
        bool verified;
        bytes32 storageRoot;
        bytes32 storageValue;
    }

    /// @notice Input parameters for storage proof verification
    /// @param stateRoot The state root of the block to verify against
    /// @param account The account to verify the storage of
    /// @param slot The slot to verify the storage of
    /// @param expectedValue The expected value of the storage slot
    struct StorageProofParams {
        bytes32 stateRoot;
        address account;
        bytes32 slot;
        bytes32 expectedValue;
    }

    /// @notice View function to verify storage proof
    /// @param params The verification parameters
    /// @param accountProof RLP-encoded account proof nodes
    /// @param storageProof RLP-encoded storage proof nodes
    /// @return result The verification result
    function verifyEthGetProof(
        StorageProofParams calldata params,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    ) external pure returns (StorageProofResult memory result) {
        bytes memory accountKey = abi.encodePacked(keccak256(abi.encodePacked(params.account)));
        bytes memory accountRlp = MerkleTrie.get(accountKey, accountProof, params.stateRoot);
        RLPReader.RLPItem[] memory accountFields = RLPReader.readList(accountRlp);

        if (accountFields.length != 4) revert InvalidAccountRLP();

        bytes memory storageRootBytes = RLPReader.readBytes(accountFields[ACCOUNT_STORAGE_ROOT_INDEX]);
        if (storageRootBytes.length == 0 || storageRootBytes.length > 32) revert InvalidAccountRLP();
        result.storageRoot = _bytesToBytes32(storageRootBytes);

        bytes memory storageKey = abi.encodePacked(keccak256(abi.encodePacked(params.slot)));
        bytes memory storageValue = MerkleTrie.get(storageKey, storageProof, result.storageRoot);

        if (storageValue.length == 0) {
            result.storageValue = bytes32(0);
            result.verified = (params.expectedValue == bytes32(0));
        } else {
            result.storageValue = _bytesToBytes32(storageValue);
            result.verified = (result.storageValue == params.expectedValue);
        }
    }

    /// @notice Convert RLP bytes to bytes32 (big-endian)
    function _bytesToBytes32(bytes memory data) private pure returns (bytes32 value) {
        if (data.length == 0) {
            return bytes32(0);
        }
        if (data.length > 32) revert InvalidStorageValue();

        assembly {
            value := mload(add(data, 32))
        }

        if (data.length < 32) {
            uint256 shift = (32 - data.length) * 8;
            value = bytes32(uint256(value) >> shift);
        }
    }
}
