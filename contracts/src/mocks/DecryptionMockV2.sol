// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {
    PUBLIC_DECRYPT_COUNTER_BASE,
    USER_DECRYPT_COUNTER_BASE
} from "@gateway-contracts/shared/KMSRequestCounters.sol";
import {BenchmarkGasUtils} from "./BenchmarkGasUtils.sol";

/**
 * @title DecryptionMockV2
 * @notice Simplified 2-state decryption flow for throughput benchmarking
 * @dev Implements a trusted response pattern without ACL checks.
 *      Supports both Public and User decryption flows with minimal overhead.
 *
 * State machine for each request:
 *   NOT_REQUESTED -> REQUESTED -> DONE
 *
 * Gas optimizations vs Decryption.sol:
 *   - No ACL checks. Assumed to be done by Centralized Gateway.
 *   - No EIP712 signature validation. Assumed to be done by Centralized Gateway.
 *   - No consensus mechanism overhead (single response completes the request)
 *   - Simplified storage layout
 */
contract DecryptionMockV2 {
    // ======================= ENUMS =======================

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
    mapping(uint256 => RequestStatus) public requestStatus;

    /// @notice Stored ciphertext handles for each public decryption request
    mapping(uint256 => bytes32[]) internal _publicCtHandles;

    /// @notice Stored payload for each user decryption request (publicKey + ctHandles)
    mapping(uint256 => UserDecryptionPayload) internal _userDecryptionPayloads;

    /// @notice Commitment hash for each completed decryption (for future verification)
    mapping(uint256 => bytes32) public responseCommitments;

    // ======================= STRUCTS =======================

    /**
     * @notice The publicKey and ctHandles from user decryption requests
     * @dev Mirrors Decryption.sol structure
     */
    struct UserDecryptionPayload {
        bytes publicKey;
        bytes32[] ctHandles;
    }

    // ======================= EVENTS =======================
    // Event signatures match IDecryption.sol where applicable

    /**
     * @notice Emitted when a public decryption request is made
     * @param decryptionId The decryption request ID
     * @param ctHandles The handles of the ciphertexts to decrypt
     * @param extraData Generic bytes metadata
     */
    event PublicDecryptionRequest(
        uint256 indexed decryptionId,
        bytes32[] ctHandles,
        bytes extraData
    );

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

    /**
     * @notice Emitted when a user decryption request is made
     * @param decryptionId The decryption request ID
     * @param ctHandles The handles of the ciphertexts to decrypt
     * @param userAddress The user's address
     * @param publicKey The user's public key for reencryption
     * @param extraData Generic bytes metadata
     */
    event UserDecryptionRequest(
        uint256 indexed decryptionId,
        bytes32[] ctHandles,
        address userAddress,
        bytes publicKey,
        bytes extraData
    );

    /**
     * @notice Emitted when a user decryption response is received
     * @param decryptionId The decryption request ID
     * @param userDecryptedShares Array of decryption shares from all KMS nodes (aggregated by Gateway)
     * @param extraData Generic bytes metadata
     */
    event UserDecryptionResponse(
        uint256 indexed decryptionId,
        bytes[] userDecryptedShares,
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

    // ======================= PUBLIC DECRYPTION =======================

    /**
     * @notice Request public decryption of ciphertext handles
     * @dev Simplified version - no ACL checks, auto-generated decryptionId
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

        // Generate a globally unique decryptionId for the public decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a public decryption request, with format: [0000 0001 | counter_1..31]
        publicDecryptionCounter++;
        decryptionId = publicDecryptionCounter;

        // Store request and transition to REQUESTED
        requestStatus[decryptionId] = RequestStatus.REQUESTED;
        _publicCtHandles[decryptionId] = ctHandles;

        // Collect the fee from the transaction sender
        _collectPublicDecryptionFee(msg.sender);

        emit PublicDecryptionRequest(decryptionId, ctHandles, extraData);
    }

    /**
     * @notice Respond to a public decryption request
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
     * @dev Simplified version - no ACL checks, no signature validation, auto-generated decryptionId
     * @param ctHandles Array of ciphertext handles to decrypt
     * @param publicKey The user's public key for reencryption
     * @param extraData Generic bytes metadata
     * @return decryptionId The generated decryption request ID
     */
    function userDecryptionRequest(
        bytes32[] calldata ctHandles,
        bytes calldata publicKey,
        bytes calldata extraData
    ) external returns (uint256 decryptionId) {
        if (ctHandles.length == 0) {
            revert EmptyCtHandles();
        }

        // Generate a globally unique decryptionId for the user decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a user decryption request, with format: [0000 0010 | counter_1..31]
        userDecryptionCounter++;
        decryptionId = userDecryptionCounter;

        // Store request and transition to REQUESTED
        requestStatus[decryptionId] = RequestStatus.REQUESTED;
        _userDecryptionPayloads[decryptionId] = UserDecryptionPayload({
            publicKey: publicKey,
            ctHandles: ctHandles
        });

        // Collect the fee from the transaction sender
        _collectUserDecryptionFee(msg.sender);

        emit UserDecryptionRequest(
            decryptionId,
            ctHandles,
            msg.sender,
            publicKey,
            extraData
        );
    }

    /**
     * @notice Respond to a user decryption request
     * @dev Simplified version - no signature validation, single response completes request.
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

        emit UserDecryptionResponse(decryptionId, userDecryptedShares, extraData);
    }

    // ======================= VIEW FUNCTIONS =======================

    /**
     * @notice Get the ciphertext handles for a public decryption request
     */
    function getPublicCtHandles(
        uint256 decryptionId
    ) external view returns (bytes32[] memory) {
        return _publicCtHandles[decryptionId];
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
        UserDecryptionPayload storage payload = _userDecryptionPayloads[
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
