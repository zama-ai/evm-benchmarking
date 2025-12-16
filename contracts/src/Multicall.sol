pragma solidity ^0.8.10;

import {Multicall3} from "@multicall3/Multicall3.sol";

contract Multicall is Multicall3 {
    constructor() Multicall3() {}
}
