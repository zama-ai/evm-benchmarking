// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {
    PUBLIC_DECRYPT_COUNTER_BASE,
    USER_DECRYPT_COUNTER_BASE
} from "@gateway-contracts/shared/KMSRequestCounters.sol";
import {BenchmarkGasUtils} from "./BenchmarkGasUtils.sol";
import {IDecryption} from "@gateway-contracts/interfaces/IDecryption.sol";
import {SnsCiphertextMaterial, CtHandleContractPair} from "@gateway-contracts/shared/Structs.sol";

/**
 * @title DecryptionMockV2
 * @notice Mock contract for benchmarking decryption request throughput
 * @dev Mirrors real Decryption.sol function signatures exactly.
 *      Mocks external calls (ACL checks, fee collection, signature validation) with gas simulation.
 *      Only implements REQUEST flows - no response/fulfill functions.
 */
contract DecryptionMockV2 {
    // ======================= STRUCTS =======================
    // Note: EIP712 verification structs removed - using off-chain commitment verification instead

    // ======================= CONSTANTS =======================

    uint16 internal constant MAX_USER_DECRYPT_DURATION_DAYS = 365;
    uint8 internal constant MAX_USER_DECRYPT_CONTRACT_ADDRESSES = 10;
    uint256 internal constant MAX_DECRYPTION_REQUEST_BITS = 2048;

    // ======================= STORAGE =======================

    /// @notice The number of public decryption requests, used to generate request IDs (`decryptionId`).
    uint256 public publicDecryptionCounter;

    /// @notice The number of user decryption requests, used to generate request IDs (`decryptionId`).
    uint256 public userDecryptionCounter;

    /// @notice Whether a (public, user, delegated user) decryption is done
    mapping(uint256 decryptionId => bool decryptionDone) public decryptionDone;

    /// @notice Handles of the ciphertexts requested for a public decryption
    mapping(uint256 decryptionId => bytes32[] ctHandles) internal publicCtHandles;

    /// @notice The digest of the signed struct on which consensus was reached for a decryption request.
    mapping(uint256 decryptionId => bytes32 consensusDigest) public decryptionConsensusDigest;


    /// @notice The KMS transaction senders involved in consensus (for mock, stored as empty array)
    mapping(uint256 decryptionId => mapping(bytes32 digest => address[] kmsTxSenderAddresses))
        internal consensusTxSenderAddresses;

    /// @notice Data commitment for user decryption requests (hash of off-chain data)
    /// @dev KMS connectors verify hash(publicKey, signature, extraData) == dataCommitment
    mapping(uint256 decryptionId => bytes32 dataCommitment) public userDecryptionDataCommitments;

    // ======================= ERRORS =======================

    error EmptyCtHandles();
    error EmptyCtHandleContractPairs();
    error EmptyContractAddresses();
    error ContractAddressesMaxLengthExceeded(uint256 maxLength, uint256 actualLength);
    error MaxDecryptionRequestBitSizeExceeded(uint256 maxBitSize, uint256 totalBitSize);
    error InvalidNullDurationDays();
    error MaxDurationDaysExceeded(uint256 maxValue, uint256 actualValue);
    error StartTimestampInFuture(uint256 currentTimestamp, uint256 startTimestamp);
    error UserDecryptionRequestExpired(uint256 currentTimestamp, IDecryption.RequestValidity requestValidity);
    error UserAddressInContractAddresses(address userAddress, address[] contractAddresses);
    error DelegatorAddressInContractAddresses(address delegatorAddress, address[] contractAddresses);
    error ContractNotInContractAddresses(address contractAddress, address[] contractAddresses);
    error CtHandleChainIdDiffersFromContractChainId(bytes32 ctHandle, uint256 chainId, uint256 contractChainId);
    error DifferentKeyIdsNotAllowed(
        SnsCiphertextMaterial firstSnsCtMaterial,
        SnsCiphertextMaterial invalidSnsCtMaterial
    );
    error DecryptionNotRequested(uint256 decryptionId);

    // ======================= EVENTS =======================

    /**
     * @notice Emitted when a user decryption request is made with data commitment
     * @param decryptionId The decryption request ID
     * @param snsCtMaterials The SNS ciphertext materials
     * @param userAddress The user's address
     * @param dataCommitment Hash commitment of off-chain data (publicKey, signature, extraData)
     */
    event UserDecryptionRequestWithCommitment(
        uint256 indexed decryptionId,
        SnsCiphertextMaterial[] snsCtMaterials,
        address userAddress,
        bytes32 dataCommitment
    );

    /**
     * @notice Emitted when a delegated user decryption request is made with data commitment
     * @param decryptionId The decryption request ID
     * @param snsCtMaterials The SNS ciphertext materials
     * @param delegateAddress The delegate's address
     * @param dataCommitment Hash commitment of off-chain data (publicKey, signature, extraData)
     */
    event DelegatedUserDecryptionRequestWithCommitment(
        uint256 indexed decryptionId,
        SnsCiphertextMaterial[] snsCtMaterials,
        address delegateAddress,
        bytes32 dataCommitment
    );

    // ======================= CONSTRUCTOR =======================

    constructor() {
        // Initialize counters with base values to generate globally unique request IDs
        // Format: [request_type_byte | counter_bytes_1..31]
        publicDecryptionCounter = PUBLIC_DECRYPT_COUNTER_BASE;
        userDecryptionCounter = USER_DECRYPT_COUNTER_BASE;
    }

    // ======================= MOCKED EXTERNAL CALLS =======================

    /**
     * @notice Collect fee for public decryption request (no-op for benchmark)
     * @dev Simulates ProtocolPaymentUtils._collectPublicDecryptionFee() internal call
     */
    function _collectPublicDecryptionFee(address /* sender */) internal virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Collect fee for user decryption request (no-op for benchmark)
     * @dev Simulates ProtocolPaymentUtils._collectUserDecryptionFee() internal call
     */
    function _collectUserDecryptionFee(address /* sender */) internal virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Mock ACL check for public decryption allowance
     * @dev Simulates MultichainACLChecks._checkIsPublicDecryptAllowed() internal call
     */
    function _checkIsPublicDecryptAllowed(bytes32 /* ctHandle */) internal view virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Mock ACL check for account allowance
     * @dev Simulates MultichainACLChecks._checkIsAccountAllowed() internal call
     */
    function _checkIsAccountAllowed(bytes32 /* ctHandle */, address /* account */) internal view virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Mock check for user decryption delegation
     * @dev Simulates MultichainACLChecks._checkIsUserDecryptionDelegated() internal call
     */
    function _checkIsUserDecryptionDelegated(
        uint256 /* chainId */,
        address /* delegatorAddress */,
        address /* delegateAddress */,
        address[] memory /* contractAddresses */
    ) internal view virtual {
        BenchmarkGasUtils.simulateExternalCall();
    }

    /**
     * @notice Mock check for registered host chain
     * @dev Simulates GatewayConfigChecks.onlyRegisteredHostChain() modifier check
     */
    function _checkIsRegisteredHostChain(uint256 /* chainId */) internal view virtual {
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

    // Note: EIP712 signature validation functions removed - using off-chain commitment verification instead

    // ======================= PUBLIC DECRYPTION REQUEST =======================

    /**
     * @notice See {IDecryption-publicDecryptionRequest}.
     */
    function publicDecryptionRequest(
        bytes32[] calldata ctHandles,
        bytes calldata extraData
    ) external virtual {
        // Check that the list of handles is not empty
        if (ctHandles.length == 0) {
            revert EmptyCtHandles();
        }

        // Check the handles' conformance
        _checkCtHandlesConformancePublic(ctHandles);

        // Fetch the SNS ciphertexts from the CiphertextCommits contract
        SnsCiphertextMaterial[] memory snsCtMaterials = _getSnsCiphertextMaterials(ctHandles);

        // Check that received snsCtMaterials have the same keyId.
        _checkCtMaterialKeyIds(snsCtMaterials);

        // Generate a globally unique decryptionId for the public decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a public decryption request, with format: [0000 0001 | counter_1..31]
        publicDecryptionCounter++;
        uint256 publicDecryptionId = publicDecryptionCounter;

        // The handles are used during response calls for the EIP712 signature validation.
        publicCtHandles[publicDecryptionId] = ctHandles;

        // Collect the fee from the transaction sender for this public decryption request.
        _collectPublicDecryptionFee(msg.sender);

        emit IDecryption.PublicDecryptionRequest(publicDecryptionId, snsCtMaterials, extraData);
    }

    // ======================= USER DECRYPTION REQUEST =======================

    /**
     * @notice User decryption request with data commitment (optimized for lower payload size)
     * @dev Instead of on-chain signature validation, stores a commitment hash.
     *      KMS connectors receive the full data off-chain and verify hash(publicKey, signature, extraData) == dataCommitment.
     */
    function userDecryptionRequest(
        CtHandleContractPair[] calldata ctHandleContractPairs,
        IDecryption.RequestValidity calldata requestValidity,
        IDecryption.ContractsInfo calldata contractsInfo,
        address userAddress,
        bytes32 dataCommitment
    ) external virtual {
        _checkIsRegisteredHostChain(contractsInfo.chainId);

        if (contractsInfo.addresses.length == 0) {
            revert EmptyContractAddresses();
        }
        if (contractsInfo.addresses.length > MAX_USER_DECRYPT_CONTRACT_ADDRESSES) {
            revert ContractAddressesMaxLengthExceeded(
                MAX_USER_DECRYPT_CONTRACT_ADDRESSES,
                contractsInfo.addresses.length
            );
        }

        // Check the user decryption request is valid.
        _checkUserDecryptionRequestValidity(requestValidity);

        // Check the user address is not included in the contract addresses.
        if (_containsContractAddress(contractsInfo.addresses, userAddress)) {
            revert UserAddressInContractAddresses(userAddress, contractsInfo.addresses);
        }

        // Extract the handles and check their conformance
        bytes32[] memory ctHandles = _extractCtHandlesCheckConformanceUser(
            ctHandleContractPairs,
            contractsInfo,
            userAddress
        );

        // Note: EIP712 signature validation removed - verification happens off-chain by KMS connectors

        // Fetch the ciphertexts from the CiphertextCommits contract
        SnsCiphertextMaterial[] memory snsCtMaterials = _getSnsCiphertextMaterials(ctHandles);

        // Check that received snsCtMaterials have the same keyId.
        _checkCtMaterialKeyIds(snsCtMaterials);

        // Generate a globally unique decryptionId for the user decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a user decryption request (including delegated user decryption requests),
        // with format: [0000 0010 | counter_1..31]
        userDecryptionCounter++;
        uint256 userDecryptionId = userDecryptionCounter;

        // Store the data commitment for KMS connectors to verify off-chain
        userDecryptionDataCommitments[userDecryptionId] = dataCommitment;

        // Collect the fee from the transaction sender for this user decryption request.
        _collectUserDecryptionFee(msg.sender);

        // Emit event with dataCommitment instead of full data (publicKey, signature, extraData)
        emit UserDecryptionRequestWithCommitment(userDecryptionId, snsCtMaterials, userAddress, dataCommitment);
    }

    // ======================= DELEGATED USER DECRYPTION REQUEST =======================

    /**
     * @notice Delegated user decryption request with data commitment (optimized for lower payload size)
     * @dev Instead of on-chain signature validation, stores a commitment hash.
     *      KMS connectors receive the full data off-chain and verify hash(publicKey, signature, extraData) == dataCommitment.
     */
    function delegatedUserDecryptionRequest(
        CtHandleContractPair[] calldata ctHandleContractPairs,
        IDecryption.RequestValidity calldata requestValidity,
        IDecryption.DelegationAccounts calldata delegationAccounts,
        IDecryption.ContractsInfo calldata contractsInfo,
        bytes32 dataCommitment
    ) external virtual {
        _checkIsRegisteredHostChain(contractsInfo.chainId);

        if (contractsInfo.addresses.length == 0) {
            revert EmptyContractAddresses();
        }
        if (contractsInfo.addresses.length > MAX_USER_DECRYPT_CONTRACT_ADDRESSES) {
            revert ContractAddressesMaxLengthExceeded(
                MAX_USER_DECRYPT_CONTRACT_ADDRESSES,
                contractsInfo.addresses.length
            );
        }

        // Check the user decryption request is valid.
        _checkUserDecryptionRequestValidity(requestValidity);

        // Check the delegator address is not included in the contract addresses.
        if (_containsContractAddress(contractsInfo.addresses, delegationAccounts.delegatorAddress)) {
            revert DelegatorAddressInContractAddresses(delegationAccounts.delegatorAddress, contractsInfo.addresses);
        }

        // Extract the handles and check their conformance.
        bytes32[] memory ctHandles = _extractCtHandlesCheckConformanceUser(
            ctHandleContractPairs,
            contractsInfo,
            delegationAccounts.delegatorAddress
        );

        // Check that the delegate address has been granted access to the contract addresses by the delegator.
        _checkIsUserDecryptionDelegated(
            contractsInfo.chainId,
            delegationAccounts.delegatorAddress,
            delegationAccounts.delegateAddress,
            contractsInfo.addresses
        );

        // Note: EIP712 signature validation removed - verification happens off-chain by KMS connectors

        // Fetch the ciphertexts from the CiphertextCommits contract.
        SnsCiphertextMaterial[] memory snsCtMaterials = _getSnsCiphertextMaterials(ctHandles);

        // Check that received snsCtMaterials have the same keyId.
        _checkCtMaterialKeyIds(snsCtMaterials);

        // Generate a globally unique decryptionId for the delegated user decryption request.
        // The counter is initialized at deployment such that decryptionId's first byte uniquely
        // represents a user decryption request (including delegated user decryption requests),
        // with format: [0000 0010 | counter_1..31].
        userDecryptionCounter++;
        uint256 userDecryptionId = userDecryptionCounter;

        // Store the data commitment for KMS connectors to verify off-chain
        userDecryptionDataCommitments[userDecryptionId] = dataCommitment;

        // Collect the fee from the transaction sender for this delegated user decryption request.
        _collectUserDecryptionFee(msg.sender);

        // Emit event with dataCommitment instead of full data (publicKey, signature, extraData)
        emit DelegatedUserDecryptionRequestWithCommitment(
            userDecryptionId,
            snsCtMaterials,
            delegationAccounts.delegateAddress,
            dataCommitment
        );
    }

    // ======================= VIEW FUNCTIONS =======================

    /**
     * @dev See {IDecryption-isPublicDecryptionReady}.
     */
    function isPublicDecryptionReady(
        bytes32[] calldata ctHandles,
        bytes calldata /* extraData */
    ) external view virtual returns (bool) {
        // Return false if the list of handles is empty
        if (ctHandles.length == 0) {
            return false;
        }

        // For mock: assume all handles are ready (external ACL/commit checks mocked)
        return true;
    }

    /**
     * @dev See {IDecryption-isUserDecryptionReady}.
     */
    function isUserDecryptionReady(
        address /* userAddress */,
        CtHandleContractPair[] calldata ctHandleContractPairs,
        bytes calldata /* extraData */
    ) external view virtual returns (bool) {
        // Return false if the list of handles is empty
        if (ctHandleContractPairs.length == 0) {
            return false;
        }

        // For mock: assume all handles are ready (external ACL/commit checks mocked)
        return true;
    }

    /**
     * @dev See {IDecryption-isDelegatedUserDecryptionReady}.
     */
    function isDelegatedUserDecryptionReady(
        IDecryption.DelegationAccounts calldata /* delegationAccounts */,
        CtHandleContractPair[] calldata ctHandleContractPairs,
        bytes calldata /* extraData */
    ) external view virtual returns (bool) {
        if (ctHandleContractPairs.length == 0) {
            return false;
        }

        // For mock: assume all handles are ready (external delegation/ACL/commit checks mocked)
        return true;
    }

    /**
     * @notice See {IDecryption-isDecryptionDone}.
     */
    function isDecryptionDone(uint256 decryptionId) external view virtual returns (bool) {
        return decryptionDone[decryptionId];
    }

    /**
     * @notice See {IDecryption-getDecryptionConsensusTxSenders}.
     */
    function getDecryptionConsensusTxSenders(uint256 decryptionId) external view virtual returns (address[] memory) {
        // Get the unique digest associated to the decryption request
        bytes32 consensusDigest = decryptionConsensusDigest[decryptionId];
        return consensusTxSenderAddresses[decryptionId][consensusDigest];
    }

    /**
     * @notice See {IDecryption-getVersion}.
     */
    function getVersion() external pure virtual returns (string memory) {
        return "DecryptionMockV2 v0.3.0";
    }

    // ======================= INTERNAL HELPERS =======================

    /**
     * @notice Check the handles' conformance for public decryption requests.
     * @dev Checks include:
     * @dev - Total bit size for each handle
     * @dev - FHE type validity for each handle
     * @dev - Handles are allowed for public decryption
     * @param ctHandles The list of ciphertext handles
     */
    function _checkCtHandlesConformancePublic(bytes32[] memory ctHandles) internal view virtual {
        // Mock: Simplified conformance check
        for (uint256 i = 0; i < ctHandles.length; i++) {
            bytes32 ctHandle = ctHandles[i];
            // Check that the handles are allowed for public decryption.
            _checkIsPublicDecryptAllowed(ctHandle);
        }
    }

    /**
     * @notice Extracts the handles and check their conformance for user decryption requests.
     * @dev Checks include:
     * @dev - Total bit size for each handle
     * @dev - FHE type validity for each handle
     * @dev - Contract addresses have access to the handles
     * @dev - Allowed address has access to the handles
     * @dev - Contract address inclusion in the list of allowed contract addresses
     * @param ctHandleContractPairs The list of ciphertext handles and contract addresses
     * @param contractsInfo The contracts' information (chain ID, addresses).
     * @param allowedAddress The address that is allowed to access the handles
     * @return ctHandles The list of ciphertext handles
     */
    function _extractCtHandlesCheckConformanceUser(
        CtHandleContractPair[] calldata ctHandleContractPairs,
        IDecryption.ContractsInfo calldata contractsInfo,
        address allowedAddress
    ) internal view virtual returns (bytes32[] memory ctHandles) {
        // Check that the list of ctHandleContractPair is not empty
        if (ctHandleContractPairs.length == 0) {
            revert EmptyCtHandleContractPairs();
        }

        ctHandles = new bytes32[](ctHandleContractPairs.length);

        for (uint256 i = 0; i < ctHandleContractPairs.length; i++) {
            bytes32 ctHandle = ctHandleContractPairs[i].ctHandle;
            address contractAddress = ctHandleContractPairs[i].contractAddress;

            // Check that the allowed and contract accounts have access to the handles.
            _checkIsAccountAllowed(ctHandle, allowedAddress);
            _checkIsAccountAllowed(ctHandle, contractAddress);

            // Check the contract is included in the list of allowed contract addresses.
            if (!_containsContractAddress(contractsInfo.addresses, contractAddress)) {
                revert ContractNotInContractAddresses(contractAddress, contractsInfo.addresses);
            }

            ctHandles[i] = ctHandle;
        }
    }

    /**
     * @notice Checks if a user decryption request's start timestamp and duration days are valid.
     * @param requestValidity The RequestValidity structure
     */
    function _checkUserDecryptionRequestValidity(
        IDecryption.RequestValidity calldata requestValidity
    ) internal view virtual {
        // Check the durationDays is not null.
        if (requestValidity.durationDays == 0) {
            revert InvalidNullDurationDays();
        }
        // Check the durationDays does not exceed the maximum allowed.
        if (requestValidity.durationDays > MAX_USER_DECRYPT_DURATION_DAYS) {
            revert MaxDurationDaysExceeded(MAX_USER_DECRYPT_DURATION_DAYS, requestValidity.durationDays);
        }

        // Check the start timestamp is not set in the future.
        if (requestValidity.startTimestamp > block.timestamp) {
            revert StartTimestampInFuture(block.timestamp, requestValidity.startTimestamp);
        }

        // Check the user decryption request has not expired.
        if (requestValidity.startTimestamp + requestValidity.durationDays * 1 days < block.timestamp) {
            revert UserDecryptionRequestExpired(block.timestamp, requestValidity);
        }
    }

    /**
     * @notice Checks if a given contractAddress is included in the contractAddresses list.
     * @param contractAddresses The list of contract addresses
     * @param contractAddress The contract address to check
     * @return Whether the contract address is included in the list
     */
    function _containsContractAddress(
        address[] memory contractAddresses,
        address contractAddress
    ) internal pure virtual returns (bool) {
        for (uint256 i = 0; i < contractAddresses.length; i++) {
            if (contractAddresses[i] == contractAddress) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Checks that all SNS ciphertext materials have the same keyId.
     * @param snsCtMaterials The list of SNS ciphertext materials to check
     */
    function _checkCtMaterialKeyIds(SnsCiphertextMaterial[] memory snsCtMaterials) internal pure virtual {
        if (snsCtMaterials.length <= 1) return;

        uint256 firstKeyId = snsCtMaterials[0].keyId;
        for (uint256 i = 1; i < snsCtMaterials.length; i++) {
            if (snsCtMaterials[i].keyId != firstKeyId) {
                revert DifferentKeyIdsNotAllowed(snsCtMaterials[0], snsCtMaterials[i]);
            }
        }
    }

    // ======================= LEGACY VIEW FUNCTIONS =======================

    /**
     * @notice Get the ciphertext handles for a public decryption request
     * @dev Legacy function for backward compatibility
     */
    function getPublicCtHandles(uint256 decryptionId) external view returns (bytes32[] memory) {
        return publicCtHandles[decryptionId];
    }

}
