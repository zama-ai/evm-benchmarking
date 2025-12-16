// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BenchmarkGasUtils} from "./mocks/BenchmarkGasUtils.sol";

/// @title ArbitraryExecution - contract to execute arbitrary operations (SSTOREs, events, calldata)
/// @notice The contract provides separate functions to benchmark storage writes, event emission, and calldata size.
contract ArbitraryExecution {
    /// @dev Emitted with `nEvents` bytes of data.
    /// Contains one topic (event signature) and `nEvents` bytes of data.
    event ContractEvent(bytes data);

    /// @dev Mapping written at increasing keys to ensure writes to previously unallocated storage slots.
    mapping(uint256 => bool) private touched;
    /// @dev Next fresh key to use in the mapping.
    uint256 public nextKey;

    /// @notice Initializes the contract. Warms up the `nextKey` storage slot.
    constructor() {
        nextKey = 1;
    }

    /// @notice Execute `nSstore` cold storage writes + 1 hot storage write.
    /// @param nSstore Number of SSTOREs to execute (writes to new storage slots each call).
    function runSstore(uint256 nSstore) external {
        // Use fresh storage slots: zero -> true at keys [start, start + nSstore)
        uint256 start = nextKey;
        for (uint256 i = 0; i < nSstore; ++i) {
            touched[start + i] = true;
        }
        nextKey = start + nSstore;
    }

    /// @notice Emit a single event with `nEvents` bytes of data.
    /// @param nEvents Number of bytes to emit in the event data.
    function runEvents(uint256 nEvents) external {
        bytes memory data = new bytes(nEvents);
        // Copy from contract bytecode (starting from byte 0) to create the bytes array
        // CODECOPY gas is the same as CALDATACOPY gas
        // solhint-disable-next-line no-inline-assembly
        assembly {
            codecopy(add(data, 0x20), 0, nEvents)
        }
        emit ContractEvent(data);
    }

    /// @notice Receive calldata of arbitrary size.
    /// @param payload Arbitrary calldata to control calldata size.
    // solhint-disable-next-line no-empty-blocks
    function runCalldata(bytes calldata payload) external {
        // Function body is intentionally empty - the calldata size is the point
    }

    function runBurnGas(uint256 gasToBurn) external pure {
        BenchmarkGasUtils.burnGas(gasToBurn);
    }

    /// @notice Execute both storage writes and event emission.
    /// @param nSstore Number of SSTOREs to execute (writes to new storage slots each call).
    /// @param nEvents Number of bytes to emit in the event data.
    function runBoth(uint256 nSstore, uint256 nEvents) external {
        this.runSstore(nSstore);
        this.runEvents(nEvents);
    }
}
