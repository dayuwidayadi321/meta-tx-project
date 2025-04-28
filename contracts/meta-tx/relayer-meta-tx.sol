// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

interface IProxy {
    function upgradeTo(address newImplementation) external;
}

contract RelayerMetaTransaction {
    string public name = "RelayerMetaTransaction";
    string public version = "2.1";

    address public owner;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public relayerWhitelist;
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address user,address target,bytes data,uint256 value,uint256 fee,uint256 nonce,uint256 chainid)"
    );

    event MetaTransactionExecuted(address indexed user, address indexed target, uint256 value, bytes data, uint256 fee);
    event RelayerWhitelisted(address indexed relayer, bool isWhitelisted);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    modifier onlyRelayer() {
        require(relayerWhitelist[msg.sender], "Relayer not authorized");
        _;
    }

    // ==================== Constructor (UPDATED) ====================
    constructor() {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            chainId,
            address(this)
        ));

        owner = msg.sender;
    }

    // ==================== Function: setRelayerWhitelist ====================
    function setRelayerWhitelist(address relayer, bool isWhitelisted) external onlyOwner {
        relayerWhitelist[relayer] = isWhitelisted;
        emit RelayerWhitelisted(relayer, isWhitelisted);
    }

    // ==================== Function: verifySignature ====================
    function verifySignature(bytes32 digest, bytes memory signature, address user) internal pure returns (bool) {
        address recovered = recoverSigner(digest, signature);
        return recovered == user;
    }

    function recoverSigner(bytes32 digest, bytes memory signature) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        return ecrecover(digest, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    // ==================== Function: executeMetaTransaction ====================
    function executeMetaTransaction(
        address user,
        address target,
        bytes memory data,
        uint256 value,
        uint256 fee,
        bytes memory signature
    ) external payable onlyRelayer {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_TX_TYPEHASH,
                        user,
                        target,
                        keccak256(data),
                        value,
                        fee,
                        nonces[user],
                        block.chainid
                    )
                )
            )
        );

        require(verifySignature(digest, signature, user), "Invalid signature");

        if (fee > 0) {
            if (msg.value >= fee) {
                (bool sent, ) = msg.sender.call{value: fee}("");
                require(sent, "Fee transfer failed");
            } else {
                require(IERC20(target).transferFrom(user, msg.sender, fee), "Fee transfer failed");
            }
        }

        (bool success, ) = target.call{value: value}(data);
        require(success, "Target call failed");

        nonces[user]++;
        emit MetaTransactionExecuted(user, target, value, data, fee);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function upgradeTo(address newImplementation) external onlyOwner {
        IProxy(address(this)).upgradeTo(newImplementation);
    }
}