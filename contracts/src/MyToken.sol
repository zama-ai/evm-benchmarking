// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MyToken - simple ERC20 for benchmarking
/// @notice Mints the entire initial supply to the deployer
contract MyToken is ERC20 {
    constructor(string memory name_, string memory symbol_, uint256 initialSupply) ERC20(name_, symbol_) {
        // initialSupply is in whole tokens, with 18 decimals
        _mint(msg.sender, initialSupply * 1e18);
    }
}
