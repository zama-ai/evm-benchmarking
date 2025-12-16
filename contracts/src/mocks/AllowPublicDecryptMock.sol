// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {IMultichainACL} from "@gateway-contracts/interfaces/IMultichainACL.sol";
import {MultichainACL} from "@gateway-contracts/MultichainACL.sol";
import {
    GatewayConfigChecks
} from "@gateway-contracts/shared/GatewayConfigChecks.sol";
import {HandleOps} from "@gateway-contracts/libraries/HandleOps.sol";
import {BenchmarkGasUtils} from "./BenchmarkGasUtils.sol";

/**
 * @title AllowPublicDecryptMock
 * @notice Mock contract for benchmarking allowPublicDecrypt throughput.
 * @dev Replicates MultichainACL storage/layout (ERC-7201) and core logic while
 *      simulating modifier gas costs for realistic benchmarking.
 */
contract AllowPublicDecryptMock {
    // ----------------------------------------------------------------------------------------------
    // Storage location (ERC-7201) – mirrors MultichainACL
    // keccak256(abi.encode(uint256(keccak256("fhevm_gateway.storage.MultichainACL")) - 1)) &
    // ~bytes32(uint256(0xff))
    // ----------------------------------------------------------------------------------------------
    bytes32 private constant MULTICHAIN_ACL_STORAGE_LOCATION =
        0x7f733a54a70114addd729bcd827932a6c402ccf3920960665917bc2e6640f400;

    function _getMultichainACLStorage()
        private
        pure
        returns (MultichainACL.MultichainACLStorage storage $)
    {
        assembly {
            $.slot := MULTICHAIN_ACL_STORAGE_LOCATION
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Constants & configuration
    // ----------------------------------------------------------------------------------------------
    uint256 public immutable CONSENSUS_THRESHOLD;
    bytes32 private constant ALLOW_PUBLIC_DECRYPT_DOMAIN_SEPARATOR_HASH =
        keccak256(bytes("MultichainACL.allowPublicDecrypt"));

    // ----------------------------------------------------------------------------------------------
    // Access control simulation state
    // ----------------------------------------------------------------------------------------------
    mapping(address => bool) private allowedCoprocessors;
    mapping(bytes32 => bool) private registeredHandles;
    bool private allHandlesRegistered;

    // ----------------------------------------------------------------------------------------------
    constructor(uint256 consensusThreshold) {
        CONSENSUS_THRESHOLD = consensusThreshold;
        // Default: allow all handles to pass registration check for benchmarks.
        allHandlesRegistered = true;
    }

    // ----------------------------------------------------------------------------------------------
    // Benchmark target function
    // ----------------------------------------------------------------------------------------------
    function allowPublicDecrypt(
        bytes32 ctHandle,
        bytes calldata extraData
    )
        external
        onlyCoprocessorTxSender
        onlyHandleFromRegisteredHostChain(ctHandle)
    {
        MultichainACL.MultichainACLStorage
            storage $ = _getMultichainACLStorage();

        bytes32 allowHash = _getAllowPublicDecryptHash(ctHandle);

        if ($.allowContextId[allowHash] == 0) {
            $.allowContextId[allowHash] = 1;
        }

        if ($.allowCoprocessors[allowHash][msg.sender]) {
            revert IMultichainACL.CoprocessorAlreadyAllowedPublicDecrypt(
                ctHandle,
                msg.sender
            );
        }

        $.allowCounters[allowHash]++;
        $.allowCoprocessors[allowHash][msg.sender] = true;
        $.allowConsensusTxSenders[allowHash].push(msg.sender);

        emit IMultichainACL.AllowPublicDecrypt(ctHandle, msg.sender, extraData);

        if (
            !$.isAllowed[allowHash] &&
            _isConsensusReached($.allowCounters[allowHash])
        ) {
            $.isAllowed[allowHash] = true;
            emit IMultichainACL.AllowPublicDecryptConsensus(
                ctHandle,
                extraData
            );
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Gas-cost simulated modifiers
    // ----------------------------------------------------------------------------------------------
    modifier onlyCoprocessorTxSender() {
        _onlyCoprocessorTxSender();
        _;
    }

    modifier onlyHandleFromRegisteredHostChain(bytes32 ctHandle) {
        _onlyHandleFromRegisteredHostChain(ctHandle);
        _;
    }

    function _onlyCoprocessorTxSender() internal view {
        BenchmarkGasUtils.burnGas(BenchmarkGasUtils.ACCESS_CONTROL_GAS_COST);
        if (!(allowedCoprocessors[msg.sender] || msg.sender != address(0))) {
            revert GatewayConfigChecks.NotCoprocessorTxSender(msg.sender);
        }
    }

    function _onlyHandleFromRegisteredHostChain(
        bytes32 ctHandle
    ) internal view {
        BenchmarkGasUtils.burnGas(BenchmarkGasUtils.EXTERNAL_CALL_GAS_COST);
        if (!(allHandlesRegistered || registeredHandles[ctHandle])) {
            uint256 chainId = HandleOps.extractChainId(ctHandle);
            revert GatewayConfigChecks.HostChainNotRegistered(chainId);
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Helper functions
    // ----------------------------------------------------------------------------------------------
    function _isConsensusReached(uint256 counter) internal view returns (bool) {
        BenchmarkGasUtils.simulateExternalCall(); // simulate gateway config call
        return counter >= CONSENSUS_THRESHOLD;
    }

    function _getAllowPublicDecryptHash(
        bytes32 ctHandle
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(ALLOW_PUBLIC_DECRYPT_DOMAIN_SEPARATOR_HASH, ctHandle)
            );
    }

    // ----------------------------------------------------------------------------------------------
    // Benchmark setup utilities
    // ----------------------------------------------------------------------------------------------
    function setCoprocessor(address coprocessor, bool isAllowed) external {
        allowedCoprocessors[coprocessor] = isAllowed;
    }

    function setHandleRegistered(bytes32 ctHandle, bool isRegistered) external {
        registeredHandles[ctHandle] = isRegistered;
    }

    function setAllHandlesRegistered(bool enabled) external {
        allHandlesRegistered = enabled;
    }

    function getConsensusSenders(
        bytes32 ctHandle
    ) external view returns (address[] memory) {
        MultichainACL.MultichainACLStorage
            storage $ = _getMultichainACLStorage();
        return $.allowConsensusTxSenders[_getAllowPublicDecryptHash(ctHandle)];
    }
}
