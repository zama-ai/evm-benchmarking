// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {
    PUBLIC_DECRYPT_COUNTER_BASE,
    USER_DECRYPT_COUNTER_BASE
} from "@gateway-contracts/shared/KMSRequestCounters.sol";
import {BenchmarkGasUtils} from "./BenchmarkGasUtils.sol";
import {Decryption} from "@gateway-contracts/Decryption.sol";
import {IDecryption} from "@gateway-contracts/interfaces/IDecryption.sol";
import {SnsCiphertextMaterial, CtHandleContractPair} from "@gateway-contracts/shared/Structs.sol";

/**
 * @title DecryptionMockV2
 * @notice Simplified 2-state mock decryption flow for throughput benchmarking
 * @dev Implements a trusted response pattern without ACL checks.
 *      Supports both Public and User decryption flows with minimal overhead.
 *
 *      REQUEST FUNCTIONS: Match the real Decryption.sol signatures exactly
 *      RESPONSE FUNCTIONS: Simplified "GatewayV2" approach with single aggregator
 *
 * State machine for each request:
 *   NOT_REQUESTED -> REQUESTED -> DONE
 *   This supports eventual future FINALIZED state for public, auditable proof of response correctness.
 *
 */
contract DecryptionMockV2 {
    enum RequestStatus {
        NOT_REQUESTED,
        REQUESTED,
        DONE
    }

    // ======================= STORAGE =======================

    /// @notice The aggregator address (trusted gateway that sends responses)
    address public immutable aggregator;

    /// @notice The number of public decryption requests, used to generate request IDs (`decryptionId`).
    uint256 public publicDecryptionCounter;

    /// @notice The number of user decryption requests, used to generate request IDs (`decryptionId`).
    uint256 public userDecryptionCounter;

    /// @notice Status of each decryption request
    mapping(uint256 decryptionId => RequestStatus status) public requestStatus;

    /// @notice Handles of the ciphertexts requested for a public decryption
    mapping(uint256 decryptionId => bytes32[] ctHandles) publicCtHandles;

    /// @notice Stored payload for each user decryption request (publicKey + ctHandles)
    mapping(uint256 decryptionId => Decryption.UserDecryptionPayload payload) internal userDecryptionPayloads;

    /// @notice Commitment hash for each completed decryption (for auditability)
    mapping(uint256 decryptionId => bytes32 commitment) public responseCommitments;

        /**
     * @notice Emitted when a public decryption response completes the request
     * @param decryptionId The decryption request ID
     * @param decryptedResult The decrypted result
     * @param extraData Generic bytes metadata
     */
    event PublicDecryptionResponse(
        uint256 indexed decryptionId,
        bytes decryptedResult,
        bytes extraData
    );

    // ======================= ERRORS =======================

    error InvalidRequestStatus(
        uint256 decryptionId,
        RequestStatus expected,
        RequestStatus actual
    );
    error EmptyCtHandles();
    error DecryptionNotRequested(uint256 decryptionId);
    error OnlyAggregator(address sender, address expected);

    // ======================= MODIFIERS =======================

    /**
     * @notice Restricts function access to the aggregator (trusted gateway)
     */
    modifier onlyAggregator() {
        if (msg.sender != aggregator) {
            revert OnlyAggregator(msg.sender, aggregator);
        }
        _;
    }

    // ======================= CONSTRUCTOR =======================

    constructor() {
        // Deployer is the aggregator (trusted gateway)
        aggregator = msg.sender;

        // Initialize counters with base values to generate globally unique request IDs
        // Format: [request_type_byte | counter_bytes_1..31]
        publicDecryptionCounter = PUBLIC_DECRYPT_COUNTER_BASE;
        userDecryptionCounter = USER_DECRYPT_COUNTER_BASE;
    }

    // ======================= FEE COLLECTION =======================

    /**
     * @notice Collect fee for public decryption request (no-op for benchmark)
     * @dev Override in derived contracts to implement actual fee collection
     */
    function _collectPublicDecryptionFee(address /* sender */) internal virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Collect fee for user decryption request (no-op for benchmark)
     * @dev Override in derived contracts to implement actual fee collection
     */
    function _collectUserDecryptionFee(address /* sender */) internal virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    // ======================= MOCKED EXTERNAL CALLS =======================

    /**
     * @notice Mock ACL check for public decryption allowance
     * @dev Simulates MULTICHAIN_ACL.isPublicDecryptAllowed() external call
     */
    function _checkIsPublicDecryptAllowed(bytes32 /* ctHandle */) internal view virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Mock ACL check for account allowance
     * @dev Simulates MULTICHAIN_ACL.isAccountAllowed() external call
     */
    function _checkIsAccountAllowed(bytes32 /* ctHandle */, address /* account */) internal view virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Mock fetch of SNS ciphertext materials
     * @dev Simulates CIPHERTEXT_COMMITS.getSnsCiphertextMaterials() external call
     */
    function _getSnsCiphertextMaterials(
        bytes32[] memory ctHandles
    ) internal view virtual returns (SnsCiphertextMaterial[] memory) {
        BenchmarkGasUtils.simulateExternalCall();

        SnsCiphertextMaterial[] memory materials = new SnsCiphertextMaterial[](ctHandles.length);
        for (uint256 i = 0; i < ctHandles.length; i++) {
            materials[i] = SnsCiphertextMaterial({
                ctHandle: ctHandles[i],
                keyId: 0,
                snsCiphertextDigest: bytes32(0),
                coprocessorTxSenderAddresses: new address[](0)
            });
        }
        return materials;
    }

    /**
     * @notice Mock signature validation for user decryption request
     * @dev Simulates ECDSA.recover() and signature validation
     */
    function _validateUserDecryptRequestSignature(
        bytes calldata signature,
        address userAddress
    ) internal view virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    // ======================= PUBLIC DECRYPTION =======================

    /**
     * @notice Request public decryption of ciphertext handles
     * @dev Matches real Decryption.sol signature exactly
     * @param ctHandles Array of ciphertext handles to decrypt
     * @param extraData Generic bytes metadata
     * @return decryptionId The generated decryption request ID
     */
    function publicDecryptionRequest(
        bytes32[] calldata ctHandles,
        bytes calldata extraData
    ) external returns (uint256 decryptionId) {
        if (ctHandles.length == 0) {
            revert EmptyCtHandles();
        }

        // Mock: Check handles conformance (ACL checks)
        for (uint256 i = 0; i < ctHandles.length; i++) {
            _checkIsPublicDecryptAllowed(ctHandles[i]);
        }

        // Mock: Fetch SNS ciphertext materials
        SnsCiphertextMaterial[] memory snsCtMaterials = _getSnsCiphertextMaterials(ctHandles);

        // Generate a globally unique decryptionId for the public decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a public decryption request, with format: [0000 0001 | counter_1..31]
        publicDecryptionCounter++;
        decryptionId = publicDecryptionCounter;

        // Store request and transition to REQUESTED
        requestStatus[decryptionId] = RequestStatus.REQUESTED;
        publicCtHandles[decryptionId] = ctHandles;

        // Collect the fee from the transaction sender
        _collectPublicDecryptionFee(msg.sender);

        emit IDecryption.PublicDecryptionRequest(decryptionId, snsCtMaterials, extraData);
    }

    /**
     * @notice Respond to a public decryption request (GatewayV2: single aggregated response)
     * @dev Simplified version - no signature validation, single response completes request
     * @param decryptionId The decryption request ID
     * @param decryptedResult The decrypted result
     * @param extraData Generic bytes metadata
     */
    function publicDecryptionResponse(
        uint256 decryptionId,
        bytes calldata decryptedResult,
        bytes calldata extraData
    ) external onlyAggregator {
        // Validate decryptionId corresponds to a generated public decryption request
        if (
            decryptionId <= PUBLIC_DECRYPT_COUNTER_BASE ||
            decryptionId > publicDecryptionCounter
        ) {
            revert DecryptionNotRequested(decryptionId);
        }

        RequestStatus status = requestStatus[decryptionId];
        if (status != RequestStatus.REQUESTED) {
            revert InvalidRequestStatus(
                decryptionId,
                RequestStatus.REQUESTED,
                status
            );
        }

        // Store commitment for potential future verification
        bytes32 commitment = keccak256(
            abi.encodePacked(decryptionId, decryptedResult)
        );
        responseCommitments[decryptionId] = commitment;

        // Transition to DONE
        requestStatus[decryptionId] = RequestStatus.DONE;

        emit PublicDecryptionResponse(decryptionId, decryptedResult, extraData);
    }

    // ======================= USER DECRYPTION =======================

    /**
     * @notice Request user decryption of ciphertext handles
     * @dev Matches real Decryption.sol signature exactly
     * @param ctHandleContractPairs The ciphertexts to decrypt for associated contracts
     * @param requestValidity The validity period of the user decryption request
     * @param contractsInfo The contracts' information (chain ID, addresses)
     * @param userAddress The user's address
     * @param publicKey The user's public key for reencryption
     * @param signature The EIP712 signature to verify
     * @param extraData Generic bytes metadata
     * @return decryptionId The generated decryption request ID
     */
    function userDecryptionRequest(
        CtHandleContractPair[] calldata ctHandleContractPairs,
        IDecryption.RequestValidity calldata requestValidity,
        IDecryption.ContractsInfo calldata contractsInfo,
        address userAddress,
        bytes calldata publicKey,
        bytes calldata signature,
        bytes calldata extraData
    ) external returns (uint256 decryptionId) {
        if (ctHandleContractPairs.length == 0) {
            revert EmptyCtHandles();
        }

        // Extract handles from pairs
        bytes32[] memory ctHandles = new bytes32[](ctHandleContractPairs.length);
        for (uint256 i = 0; i < ctHandleContractPairs.length; i++) {
            ctHandles[i] = ctHandleContractPairs[i].ctHandle;

            // Mock: Check ACL for user and contract
            _checkIsAccountAllowed(ctHandleContractPairs[i].ctHandle, userAddress);
            _checkIsAccountAllowed(ctHandleContractPairs[i].ctHandle, ctHandleContractPairs[i].contractAddress);
        }

        // Mock: Validate EIP712 signature
        _validateUserDecryptRequestSignature(signature, userAddress);

        // Mock: Fetch SNS ciphertext materials
        SnsCiphertextMaterial[] memory snsCtMaterials = _getSnsCiphertextMaterials(ctHandles);

        // Generate a globally unique decryptionId for the user decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a user decryption request, with format: [0000 0010 | counter_1..31]
        userDecryptionCounter++;
        decryptionId = userDecryptionCounter;

        // Store request and transition to REQUESTED
        requestStatus[decryptionId] = RequestStatus.REQUESTED;
        userDecryptionPayloads[decryptionId] = Decryption.UserDecryptionPayload({
            publicKey: publicKey,
            ctHandles: ctHandles
        });

        // Collect the fee from the transaction sender
        _collectUserDecryptionFee(msg.sender);

        // Silence unused variable warnings (used for realistic calldata size)
        requestValidity;
        contractsInfo;

        // Burn additional gas to match real-world gas consumption (~800k total)
        // Real: ~800k, Current: ~360k, Delta: ~450k
        BenchmarkGasUtils.burnGas(450_000);

        emit IDecryption.UserDecryptionRequest(
            decryptionId,
            snsCtMaterials,
            userAddress,
            publicKey,
            extraData
        );
    }

    /**
     * @notice Respond to a user decryption request (GatewayV2: single aggregated response)
     * @dev Simplified version - no signature validation, single response with all shares
     *      The Gateway aggregates all KMS node shares, verifies the signatures, and sends them in one transaction.
     * @param decryptionId The decryption request ID
     * @param userDecryptedShares Array of decryption shares from all KMS nodes
     * @param extraData Generic bytes metadata
     */
    function userDecryptionResponse(
        uint256 decryptionId,
        bytes[] calldata userDecryptedShares,
        bytes calldata extraData
    ) external onlyAggregator {
        // Validate decryptionId corresponds to a generated user decryption request
        if (
            decryptionId <= USER_DECRYPT_COUNTER_BASE ||
            decryptionId > userDecryptionCounter
        ) {
            revert DecryptionNotRequested(decryptionId);
        }

        RequestStatus status = requestStatus[decryptionId];
        if (status != RequestStatus.REQUESTED) {
            revert InvalidRequestStatus(
                decryptionId,
                RequestStatus.REQUESTED,
                status
            );
        }

        // Store commitment for potential future verification
        // Hash all shares together for the commitment
        bytes32 commitment = keccak256(
            abi.encode(decryptionId, userDecryptedShares)
        );
        responseCommitments[decryptionId] = commitment;

        // Transition to DONE
        requestStatus[decryptionId] = RequestStatus.DONE;

        emit IDecryption.UserDecryptionResponse(decryptionId, 0, userDecryptedShares[0], "", extraData);
    }

    // ======================= VIEW FUNCTIONS =======================

    /**
     * @notice Get the ciphertext handles for a public decryption request
     */
    function getPublicCtHandles(
        uint256 decryptionId
    ) external view returns (bytes32[] memory) {
        return publicCtHandles[decryptionId];
    }

    /**
     * @notice Get the user decryption payload (publicKey + ctHandles)
     */
    function getUserDecryptionPayload(
        uint256 decryptionId
    )
        external
        view
        returns (bytes memory publicKey, bytes32[] memory ctHandles)
    {
        Decryption.UserDecryptionPayload storage payload = userDecryptionPayloads[
            decryptionId
        ];
        return (payload.publicKey, payload.ctHandles);
    }

    /**
     * @notice Check if a decryption is complete
     */
    function isDecryptionDone(
        uint256 decryptionId
    ) external view returns (bool) {
        return requestStatus[decryptionId] == RequestStatus.DONE;
    }

    /**
     * @notice Get the response commitment for a completed request
     */
    function getCommitment(
        uint256 decryptionId
    ) external view returns (bytes32) {
        return responseCommitments[decryptionId];
    }
}
