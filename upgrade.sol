// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    fallback() external payable {
        address _impl = implementation;
        (bool success, ) = _impl.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }
}
