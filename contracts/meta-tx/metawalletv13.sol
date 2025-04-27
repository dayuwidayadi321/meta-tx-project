// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MetaWalletV13 is ReentrancyGuard, Pausable, Ownable {
    using ECDSA for bytes32;

    // ==================== Storage ====================
    address public smartWallet;
    bytes public userWalletBytecode;

    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isDeployed;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address user,address target,bytes data,uint256 value,uint256 fee,uint256 nonce,uint256 chainId)"
    );
    bytes32 public constant BATCH_META_TX_TYPEHASH = keccak256(
        "BatchMetaTransaction(address user,address[] targets,bytes[] datas,uint256[] values,uint256 fee,uint256 nonce,uint256 chainId)"
    );
    bytes32 public constant META_DEPLOY_TYPEHASH = keccak256(
        "MetaDeploy(address user,uint256 nonce,uint256 chainId)"
    );
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    string public constant NAME = "MetaWallet";
    string public constant VERSION = "13";

    // ==================== Events ====================
    event MetaTransactionExecuted(address indexed user, address target, uint256 value, bytes data, uint256 fee);
    event BatchMetaTransactionExecuted(address indexed user, address[] targets, uint256[] values, bytes[] datas, uint256 fee);
    event MetaWalletDeployed(address indexed user, address wallet);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event SmartWalletSet(address smartWallet);
    event WalletPaused(address indexed account);
    event WalletUnpaused(address indexed account);

    // ==================== Constructor ====================
    constructor() Ownable(0x484ee82f48Bcaf15927C06432f4c279eE3f95D46) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );      
    }

    // ==================== Function: setSmartWallet ====================
    function setSmartWallet(address _smartWallet) external onlyOwner {
        smartWallet = _smartWallet;
        emit SmartWalletSet(_smartWallet);
    }

    // ==================== Function: addRelayer ====================
    function addRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = true;
        emit RelayerAdded(relayer);
    }

    // ==================== Function: removeRelayer ====================
    function removeRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = false;
        emit RelayerRemoved(relayer);
    }

    // ==================== Function: pauseWallet ====================
    function pauseWallet() external onlyOwner {
        _pause();
        emit WalletPaused(msg.sender);
    }

    // ==================== Function: unpauseWallet ====================
    function unpauseWallet() external onlyOwner {
        _unpause();
        emit WalletUnpaused(msg.sender);
    }

    // ==================== Function: verifySignature (Internal Helper) ====================
    function verifySignature(bytes32 digest, bytes memory signature, address expectedSigner) internal pure returns (bool) {
        return digest.recover(signature) == expectedSigner;
    }

    // ==================== Function: deployUserWallet ====================
    function deployUserWallet(address user, bytes memory signature) external whenNotPaused nonReentrant {
        require(!isDeployed[user], "Already deployed");
        require(userWalletBytecode.length > 0, "Bytecode not set");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(META_DEPLOY_TYPEHASH, user, nonces[user], block.chainid))
            )
        );

        require(verifySignature(digest, signature, user), "Invalid signature");

        bytes32 salt = keccak256(abi.encodePacked(user));
        address walletAddress = Create2.deploy(0, salt, userWalletBytecode);
        
        isDeployed[user] = true;
        nonces[user]++;
        
        emit MetaWalletDeployed(user, walletAddress);
    }

    // ==================== Function: executeMetaTransaction ====================
    function executeMetaTransaction(
        address user,
        address target,
        bytes memory data,
        uint256 value,
        uint256 fee,
        bytes memory signature
    ) external payable whenNotPaused nonReentrant {
        require(relayerWhitelist[msg.sender], "Relayer not authorized");
        
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

        // Fee distribution
        if (fee > 0) {
            if (msg.value >= fee) {
                (bool sent, ) = msg.sender.call{value: fee}("");
                require(sent, "Fee transfer failed");
            } else {
                require(target.code.length > 0, "Target is not a contract");
                require(IERC20(target).transferFrom(user, msg.sender, fee), "Fee transfer failed");
            }
        }

        // Execute call
        (bool success, ) = target.call{value: value}(data);
        require(success, "Target call failed");

        nonces[user]++;
        emit MetaTransactionExecuted(user, target, value, data, fee);
    }

    // ==================== Function: executeBatchMetaTransaction ====================
    function executeBatchMetaTransaction(
        address user,
        address[] memory targets,
        bytes[] memory datas,
        uint256[] memory values,
        uint256 fee,
        bytes memory signature
    ) external payable whenNotPaused nonReentrant {
        require(relayerWhitelist[msg.sender], "Relayer not authorized");
        require(targets.length == datas.length && datas.length == values.length, "Array length mismatch");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        BATCH_META_TX_TYPEHASH,
                        user,
                        keccak256(abi.encode(targets)),
                        keccak256(abi.encode(datas)),
                        keccak256(abi.encode(values)),
                        fee,
                        nonces[user],
                        block.chainid
                    )
                )
            )
        );

        require(verifySignature(digest, signature, user), "Invalid signature");

        // Execute each call
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call{value: values[i]}(datas[i]);
            require(success, "Target call failed");
        }

        // Fee collection
        if (fee > 0) {
            require(msg.value >= fee, "Insufficient fee sent");
            (bool sent, ) = msg.sender.call{value: fee}("");
            require(sent, "Fee transfer failed");
        }

        nonces[user]++;
        emit BatchMetaTransactionExecuted(user, targets, values, datas, fee);
    }

    // ==================== Fallback function ====================
    receive() external payable {}
}