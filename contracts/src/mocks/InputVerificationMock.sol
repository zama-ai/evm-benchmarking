// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {IInputVerification} from "@gateway-contracts/interfaces/IInputVerification.sol";
import {BenchmarkGasUtils} from "./BenchmarkGasUtils.sol";

/**
 * @title InputVerificationMock
 * @notice Mock contract for benchmarking input verification request flow
 * @dev Replicates verifyProofRequest from InputVerification.sol with mocked external dependencies.
 *      All external calls (GatewayConfig, ProtocolPayment) are simulated using BenchmarkGasUtils.
 */
contract InputVerificationMock {
    // ======================= STRUCTS =======================

    /**
     * @notice The stored structure for the received ZK Proof verification request inputs.
     */
    struct ZKProofInput {
        uint256 contractChainId;
        address contractAddress;
        address userAddress;
    }

    // ======================= STORAGE =======================

    /// @notice The counter used for the ZKPoK IDs returned in verification request events.
    uint256 public zkProofIdCounter;

    /// @notice The ZKPoK request inputs to be used for signature validation in response calls.
    mapping(uint256 zkProofId => ZKProofInput zkProofInput) public zkProofInputs;

    /// @notice The coprocessor context ID associated to the input verification request.
    mapping(uint256 zkProofId => uint256 contextId) public inputVerificationContextId;

    /// @notice Mock state for pause simulation.
    bool public paused;

    // ======================= CONSTRUCTOR =======================

    constructor() {}

    // ======================= ACCESS CONTROL MODIFIERS =======================

    /**
     * @notice Simulates onlyRegisteredHostChain modifier with realistic gas cost
     * @dev Burns gas to simulate GatewayConfig.isHostChainRegistered() external call
     */
    modifier onlyRegisteredHostChain(uint256 /* chainId */) {
        BenchmarkGasUtils.simulateExternalCall();
        _;
    }

    /**
     * @notice Simulates whenNotPaused modifier with realistic gas cost
     */
    modifier whenNotPaused() {
        BenchmarkGasUtils.burnGas(BenchmarkGasUtils.ACCESS_CONTROL_GAS_COST / 2);
        require(!paused, "Contract is paused");
        _;
    }

    // ======================= MAIN FUNCTION =======================

    /**
     * @notice See {IInputVerification-verifyProofRequest}.
     * @dev Replicates the full request flow with mocked external calls.
     */
    function verifyProofRequest(
        uint256 contractChainId,
        address contractAddress,
        address userAddress,
        bytes calldata ciphertextWithZKProof,
        bytes calldata extraData
    ) external virtual onlyRegisteredHostChain(contractChainId) whenNotPaused {
        zkProofIdCounter++;
        uint256 zkProofId = zkProofIdCounter;

        // Store the ZK proof inputs (used in response calls for signature validation)
        zkProofInputs[zkProofId] = ZKProofInput(contractChainId, contractAddress, userAddress);

        // Associate the request to coprocessor context ID 1
        inputVerificationContextId[zkProofId] = 1;

        // Simulate external call to collect input verification fee
        BenchmarkGasUtils.simulateExternalCall();

        emit IInputVerification.VerifyProofRequest(
            zkProofId,
            contractChainId,
            contractAddress,
            userAddress,
            ciphertextWithZKProof,
            extraData
        );
    }

    // ======================= ADMIN FUNCTIONS =======================

    /**
     * @notice Set pause state for access control simulation
     */
    function setPaused(bool _paused) external {
        paused = _paused;
    }
}
