// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {
    PUBLIC_DECRYPT_COUNTER_BASE,
    USER_DECRYPT_COUNTER_BASE
} from "@gateway-contracts/shared/KMSRequestCounters.sol";
import {IDecryption} from "@gateway-contracts/interfaces/IDecryption.sol";
import {Decryption} from "@gateway-contracts/Decryption.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    EIP712Upgradeable
} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {BenchmarkGasUtils} from "./BenchmarkGasUtils.sol";
import {
    GatewayConfigChecks
} from "@gateway-contracts/shared/GatewayConfigChecks.sol";

/**
 * @title DecryptionMock
 * @notice Mock contract for benchmarking decryption response functionality (both user and public)
 * @dev Accurately simulates gas costs and storage operations from the original Decryption contract
 * with realistic cross-contract call simulation and access control overhead
 */
contract DecryptionMock is EIP712Upgradeable {
    // Duplicate internal definitions from Decryption.sol
    /**
     * @notice Storage location has been computed using the following command:
     * keccak256(abi.encode(uint256(keccak256("fhevm_gateway.storage.Decryption")) - 1)) &
     * ~bytes32(uint256(0xff))
     */
    bytes32 private constant DECRYPTION_STORAGE_LOCATION =
        0x68113e68af494c6efd0210fc4bf9ba748d1ffadaa4718217fdf63548c4aee700;

    /**
     * @notice Returns the Decryption storage location.
     * @dev Note that this function is internal but not virtual: derived contracts should be able to
     * access it, but if the underlying storage struct version changes, we force them to define a new
     * getter function and use that one instead in order to avoid overriding the storage location.
     */
    function _getDecryptionStorage()
        internal
        pure
        returns (Decryption.DecryptionStorage storage $)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := DECRYPTION_STORAGE_LOCATION
        }
    }

    // Deploy-time configuration
    uint256 public immutable CONSENSUS_THRESHOLD;

    // ======================= CONSTANTS & STORAGE =======================

    // ======================= STORAGE STRUCTURES =======================

    mapping(address => bool) kmsSenders;

    /// @notice Mock state for access control simulation
    bool paused;

    // Constants for EIP712 hashing
    bytes32 private constant EIP712_USER_DECRYPT_RESPONSE_TYPE_HASH =
        keccak256(
            "UserDecryptResponseVerification(bytes publicKey,bytes32[] ctHandles,bytes userDecryptedShare,bytes extraData)"
        );

    bytes32 private constant EIP712_PUBLIC_DECRYPT_TYPE_HASH =
        keccak256(
            "PublicDecryptVerification(bytes32[] ctHandles,bytes decryptedResult,bytes extraData)"
        );

    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    // Template ID for fallback payload (simulates storage read cost for benchmark)
    uint256 private constant TEMPLATE_PAYLOAD_ID = 0;
    uint256 private constant TEMPLATE_PUBLIC_PAYLOAD_ID = 0;

    constructor(uint256 _consensusThreshold) {
        CONSENSUS_THRESHOLD = _consensusThreshold;
        // Initialize the decryption counters to an arbitrary very high value to "queue" some requests.
        Decryption.DecryptionStorage storage $ = _getDecryptionStorage();
        $.userDecryptionCounter = type(uint256).max - type(uint64).max;
        $.publicDecryptionCounter = type(uint256).max - type(uint64).max;

        // Initialize the template payloads
        bytes32[] memory templateCtHandles = new bytes32[](2);
        templateCtHandles[0] = 0xbefa446d0d1758d58c932820aa88740e326b978709ff0000000000aa36a70500;
        templateCtHandles[1] = 0xCD25e0e4972e075C371948c7137Bcd498C1F4e89000000000000000000000000;

        $.userDecryptionPayloads[TEMPLATE_PAYLOAD_ID] = Decryption.UserDecryptionPayload({
            publicKey: hex"f3766c6ecb51e7d30c484503a4e72a253fae5ab93cff0000000000aa36a70400",
            ctHandles: templateCtHandles
        });

        bytes32[] memory templatePublicCtHandles = new bytes32[](1);
        templatePublicCtHandles[0] = 0xf3766c6ecb51e7d30c484503a4e72a253fae5ab93cff0000000000aa36a70400;
        $.publicCtHandles[TEMPLATE_PUBLIC_PAYLOAD_ID] = templatePublicCtHandles;
    }

    // ======================= ACCESS CONTROL MODIFIERS =======================

    /**
     * @notice Simulates onlyKmsTxSender modifier with realistic gas cost
     */
    modifier onlyKmsTxSender() {
        _onlyKmsTxSender();
        _;
    }

    /**
     * @notice Simulates whenNotPaused modifier with realistic gas cost
     */
    modifier whenNotPaused() {
        _whenNotPaused();
        _;
    }

    /**
     * @notice Internal function to reduce code size for onlyKmsTxSender modifier
     */
    function _onlyKmsTxSender() internal view {
        BenchmarkGasUtils.burnGas(BenchmarkGasUtils.ACCESS_CONTROL_GAS_COST);
        _simulateKmsTxSenderCheck();
    }

    /**
     * @notice Internal function to reduce code size for whenNotPaused modifier
     */
    function _whenNotPaused() internal view {
        BenchmarkGasUtils.burnGas(
            BenchmarkGasUtils.ACCESS_CONTROL_GAS_COST / 2
        );
        require(!paused, "Contract is paused");
    }

    /**
     * @notice Main benchmarking function - mirrors userDecryptionResponse from Decryption.sol
     * @dev Includes all performance-critical operations with realistic gas simulation
     * @param decryptionId The decryption request ID
     * @param userDecryptedShare The encrypted share data
     * @param signature The KMS signature
     * @param extraData Additional versioned payload metadata
     */
    function userDecryptionResponse(
        uint256 decryptionId,
        bytes calldata userDecryptedShare,
        bytes calldata signature,
        bytes calldata extraData
    ) external onlyKmsTxSender whenNotPaused {
        Decryption.DecryptionStorage storage $ = _getDecryptionStorage();

        // Make sure the decryptionId corresponds to a generated user decryption request
        if (
            decryptionId <= USER_DECRYPT_COUNTER_BASE ||
            decryptionId > $.userDecryptionCounter
        ) {
            revert IDecryption.DecryptionNotRequested(decryptionId);
        }

        // BENCHMARK SPECIFIC:
        // Read from template ID to simulate the gas cost of
        // reading a populated struct from storage (cold read).
        Decryption.UserDecryptionPayload memory userDecryptionPayload = $
            .userDecryptionPayloads[TEMPLATE_PAYLOAD_ID];

        Decryption.UserDecryptResponseVerification memory userDecryptResponseVerification = Decryption.UserDecryptResponseVerification(
            userDecryptionPayload.publicKey,
            userDecryptionPayload.ctHandles,
            userDecryptedShare,
            extraData
        );

        // Compute the digest of the UserDecryptResponseVerification structure
        bytes32 digest = _hashUserDecryptResponseVerification(userDecryptResponseVerification);

        // Recover the signer address from the signature and validate that it corresponds to a
        // KMS node that has not already signed.
        _validateDecryptionResponseEIP712Signature(decryptionId, digest, signature);

        // Store the KMS transaction sender address for the user decryption response
        // We use a zero digest (default value for `bytes32`) to be able to retrieve the
        // list later independently of the decryption response type (public or user).
        address[] storage txSenderAddresses = $.consensusTxSenderAddresses[
            decryptionId
        ][0];
        txSenderAddresses.push(msg.sender);

        // Store the user decrypted share for the user decryption response.
        // The index of the share is the length of the txSenderAddresses - 1 so that the first response
        // associated to this decryptionId has an index of 0.
        emit IDecryption.UserDecryptionResponse(
            decryptionId,
            txSenderAddresses.length - 1,
            userDecryptedShare,
            signature,
            extraData
        );

        // Consensus check with external call simulation
        uint256 threshold = _simulateGetConsensusThreshold();

        // Send the event if and only if the consensus is reached in the current response call.
        // This means a "late" response will not be reverted, just ignored and no event will be emitted
        if (
            !$.decryptionDone[decryptionId] &&
            txSenderAddresses.length >= threshold
        ) {
            $.decryptionDone[decryptionId] = true;

            // Since we use the default value for `bytes32`, this means we do not need to store the
            // digest in `decryptionConsensusDigest` here like we do for the public decryption case.

            emit IDecryption.UserDecryptionResponseThresholdReached(
                decryptionId
            );
        }
    }

    /**
     * @notice Validates the EIP712 signature for a given decryption response.
     * @dev Used by both userDecryptionResponse and publicDecryptionResponse.
     * @param decryptionId The decryption request ID.
     * @param digest The hashed EIP712 struct.
     * @param signature The signature to validate.
     */
    function _validateDecryptionResponseEIP712Signature(
        uint256 decryptionId,
        bytes32 digest,
        bytes calldata signature
    ) internal virtual {
        Decryption.DecryptionStorage storage $ = _getDecryptionStorage();
        ECDSA.tryRecover(digest, signature);

        // BENCHMARK HACK:
        // Set signer to msg.sender to simulate a valid signature from this KMS node.
        // This allows multiple VUs (with different addresses) to submit responses
        // for the same decryptionId without colliding on the signer address,
        // enabling accurate consensus threshold testing with dummy signatures.
        address signer = msg.sender;

        // Simulate the external call to check KMS signer matches tx sender
        BenchmarkGasUtils.simulateExternalCall();

        if ($.kmsNodeAlreadySigned[decryptionId][signer]) {
            revert IDecryption.KmsNodeAlreadySigned(decryptionId, signer);
        }

        $.kmsNodeAlreadySigned[decryptionId][signer] = true;
    }

    /**
     * @notice Computes the hash of a given UserDecryptResponseVerification structured data.
     * @param userDecryptResponseVerification The UserDecryptResponseVerification structure to hash.
     * @return The hash of the UserDecryptResponseVerification structure.
     */
    function _hashUserDecryptResponseVerification(
        Decryption.UserDecryptResponseVerification memory userDecryptResponseVerification
    ) internal view virtual returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        EIP712_USER_DECRYPT_RESPONSE_TYPE_HASH,
                        keccak256(userDecryptResponseVerification.publicKey),
                        keccak256(abi.encodePacked(userDecryptResponseVerification.ctHandles)),
                        keccak256(userDecryptResponseVerification.userDecryptedShare),
                        keccak256(abi.encodePacked(userDecryptResponseVerification.extraData))
                    )
                )
            );
    }



    // ======================= PUBLIC DECRYPTION =======================

    /**
     * @notice Main benchmarking function for public decryption - mirrors publicDecryptionResponse from Decryption.sol
     * @dev Includes all performance-critical operations with realistic gas simulation
     * @param decryptionId The decryption request ID
     * @param decryptedResult The decrypted result data
     * @param signature The KMS signature
     * @param extraData Additional versioned payload metadata
     */
    function publicDecryptionResponse(
        uint256 decryptionId,
        bytes calldata decryptedResult,
        bytes calldata signature,
        bytes calldata extraData
    ) external onlyKmsTxSender {
        Decryption.DecryptionStorage storage $ = _getDecryptionStorage();

        // Make sure the decryptionId corresponds to a generated public decryption request:
        // - it must be greater than the base counter for public decryption requests
        // - it must be less than or equal to the current public decryption counter
        if (
            decryptionId <= PUBLIC_DECRYPT_COUNTER_BASE ||
            decryptionId > $.publicDecryptionCounter
        ) {
            revert IDecryption.DecryptionNotRequested(decryptionId);
        }

        // BENCHMARK SPECIFIC:
        // Read from template ID to simulate the gas cost of
        // reading a populated array from storage (cold read).
        Decryption.PublicDecryptVerification memory publicDecryptVerification = Decryption.PublicDecryptVerification(
            $.publicCtHandles[TEMPLATE_PUBLIC_PAYLOAD_ID],
            decryptedResult,
            extraData
        );


        // Compute the digest of the PublicDecryptVerification structure.
        bytes32 digest = _hashPublicDecryptVerification(publicDecryptVerification);

        // Recover the signer address from the signature and validate that it corresponds to a
        // KMS node that has not already signed.
        _validateDecryptionResponseEIP712Signature(decryptionId, digest, signature);

        // Store the signature for the public decryption response.
        // This list is then used to check the consensus. Important: the mapping considers
        // the digest (contrary to the user decryption case) as the decrypted result is expected
        // to be the same for all KMS nodes.
        bytes[] storage verifiedSignatures = $.verifiedPublicDecryptSignatures[
            decryptionId
        ][digest];
        verifiedSignatures.push(signature);

        // Store the KMS transaction sender address for the public decryption response
        $.consensusTxSenderAddresses[decryptionId][digest].push(msg.sender);

        // Emit the event at each call for monitoring purposes.
        emit IDecryption.PublicDecryptionResponseCall(
            decryptionId,
            decryptedResult,
            signature,
            msg.sender,
            extraData
        );

        // Consensus check with external call simulation
        uint256 threshold = _simulateGetConsensusThreshold();


        // Send the event if and only if the consensus is reached in the current response call.
        // This means a "late" response will not be reverted, just ignored and no event will be emitted
        if (!$.decryptionDone[decryptionId] && verifiedSignatures.length >= threshold) {
            $.decryptionDone[decryptionId] = true;

            // A "late" valid KMS could still see its transaction sender address be added to the list
            // after consensus. This storage variable is here to be able to retrieve this list later
            // by only knowing the decryption ID, since a consensus can only happen once per decryption
            // request, independently of the decryption response type (public or user).
            $.decryptionConsensusDigest[decryptionId] = digest;

            emit IDecryption.PublicDecryptionResponse(decryptionId, decryptedResult, verifiedSignatures, extraData);
        }
    }

    /**
     * @notice Computes the hash of a given PublicDecryptVerification structured data
     * @param publicDecryptVerification The PublicDecryptVerification structure
     * @return The hash of the PublicDecryptVerification structure
     */
    function _hashPublicDecryptVerification(
        Decryption.PublicDecryptVerification memory publicDecryptVerification
    ) internal view virtual returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        EIP712_PUBLIC_DECRYPT_TYPE_HASH,
                        keccak256(abi.encodePacked(publicDecryptVerification.ctHandles)),
                        keccak256(publicDecryptVerification.decryptedResult),
                        keccak256(abi.encodePacked(publicDecryptVerification.extraData))
                    )
                )
            );
    }


    // ======================= SHARED INTERNAL FUNCTIONS =======================

    function _simulateKmsTxSenderCheck() internal view {
        bool isKmsSender = kmsSenders[msg.sender] || msg.sender != address(0);
        if (!isKmsSender) {
            revert GatewayConfigChecks.NotKmsTxSender(msg.sender);
        }
    }

    /**
     * @notice Simulate getting consensus threshold with external call
     */
    function _simulateGetConsensusThreshold() internal view returns (uint256) {
        BenchmarkGasUtils.burnGas(BenchmarkGasUtils.EXTERNAL_CALL_GAS_COST);
        return CONSENSUS_THRESHOLD;
    }

    /**
     * @notice Configure KMS senders for access control simulation
     */
    function setKmsSender(address sender, bool isKms) external {
        kmsSenders[sender] = isKms;
    }

    /**
     * @notice Set pause state for access control simulation
     */
    function setPaused(bool _paused) external {
        paused = _paused;
    }

    /**
     * @notice Get current gas costs configuration for transparency
     */
    function getGasCosts()
        external
        pure
        returns (uint256 externalCall, uint256 accessControl, uint256 signature)
    {
        return (
            BenchmarkGasUtils.EXTERNAL_CALL_GAS_COST,
            BenchmarkGasUtils.ACCESS_CONTROL_GAS_COST,
            BenchmarkGasUtils.SIGNATURE_VALIDATION_GAS
        );
    }
}
