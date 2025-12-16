/* solhint-disable */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {StorageProofVerifier} from "../src/proof/StorageProofVerifier.sol";

/// @title StorageProofVerifierTest
/// @notice Tests for the StorageProofVerifier contract with gas benchmarking
contract StorageProofVerifierTest is Test {
    StorageProofVerifier public verifier;

    // Test fixture data (loaded from JSON)
    bytes32 public stateRoot;
    address public account;
    bytes32 public slot;
    bytes32 public expectedValue;

    // Account proof nodes
    bytes[] public accountProof;
    // Storage proof nodes
    bytes[] public storageProof;

    function setUp() public {
        verifier = new StorageProofVerifier();

        // Load proof from JSON file
        _loadProofFromJson("./proofs/sepolia_storage_proof.json");
    }

    function _loadProofFromJson(string memory path) internal {
        string memory json = vm.readFile(path);

        // Load params
        stateRoot = vm.parseJsonBytes32(json, ".params.stateRoot");
        account = vm.parseJsonAddress(json, ".params.account");
        slot = vm.parseJsonBytes32(json, ".params.slot");
        expectedValue = vm.parseJsonBytes32(json, ".params.expectedValue");

        // Load account proof array
        bytes[] memory accountProofData = vm.parseJsonBytesArray(json, ".accountProof");
        for (uint256 i = 0; i < accountProofData.length; i++) {
            accountProof.push(accountProofData[i]);
        }

        // Load storage proof array
        bytes[] memory storageProofData = vm.parseJsonBytesArray(json, ".storageProof");
        for (uint256 i = 0; i < storageProofData.length; i++) {
            storageProof.push(storageProofData[i]);
        }
    }

    /// @notice Test verifying a valid storage proof
    function test_VerifyStorageProof_Valid() public view {
        StorageProofVerifier.StorageProofParams memory params = StorageProofVerifier.StorageProofParams({
            stateRoot: stateRoot, account: account, slot: slot, expectedValue: expectedValue
        });

        // Cache storage arrays in memory BEFORE gas measurement
        // to avoid counting storage reads in the benchmark
        bytes[] memory accountProofMem = accountProof;
        bytes[] memory storageProofMem = storageProof;

        uint256 gasStart = gasleft();
        StorageProofVerifier.StorageProofResult memory result =
            verifier.verifyEthGetProof(params, accountProofMem, storageProofMem);
        uint256 gasEnd = gasleft();
        uint256 gasUsed = gasStart - gasEnd;
        console.log("Gas used:", gasUsed);

        assertTrue(result.verified, "Proof should be verified");
        assertEq(result.storageValue, expectedValue, "Storage value should match");
    }
}
