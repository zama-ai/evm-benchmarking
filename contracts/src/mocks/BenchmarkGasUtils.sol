// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

/**
 * @title BenchmarkGasUtils
 * @notice Shared utilities for gas cost simulation in benchmark mock contracts
 * @dev Used by DecryptionMock, AllowPublicDecryptMock, and other benchmark contracts
 *      to accurately simulate gas costs of external calls and access control checks
 */
library BenchmarkGasUtils {
    // ======================= GAS COST CONSTANTS =======================

    /// @notice Cost of CALL opcode + warm account access for external contract calls
    uint256 internal constant EXTERNAL_CALL_GAS_COST = 2600;

    /// @notice Cost of storage reads + conditional checks for access control modifiers
    uint256 internal constant ACCESS_CONTROL_GAS_COST = 800;

    /// @notice Cost of ECRECOVER precompile for signature validation
    uint256 internal constant SIGNATURE_VALIDATION_GAS = 3000;

    // ======================= GAS SIMULATION FUNCTIONS =======================

    /**
     * @notice Gas burning function to simulate computational costs
     * @dev Uses computational loops to accurately consume gas. Each iteration costs
     *      approximately 20 gas (JUMPI + arithmetic ops)
     * @param gasToBurn Amount of gas to consume through computation
     */
    function burnGas(uint256 gasToBurn) internal pure {
        uint256 iterations = gasToBurn / 20;
        uint256 dummy = 0;

        for (uint256 i = 0; i < iterations;) {
            dummy = dummy ^ i; // XOR operation to prevent optimization
            unchecked {
                ++i;
            }
        }

        // Prevent the compiler from optimizing away the loop
        assembly {
            if eq(dummy, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) {
                revert(0, 0)
            }
        }
    }

    /**
     * @notice Simulates an external contract call with realistic gas cost.
     * @dev Burns EXTERNAL_CALL_GAS_COST gas - doesn't account for calldata cost.
     */
    function simulateExternalCall() internal pure {
        burnGas(EXTERNAL_CALL_GAS_COST);
    }
}
