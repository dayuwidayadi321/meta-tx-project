// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MetaWalletV12 is ReentrancyGuard, Pausable, Ownable {
    using ECDSA for bytes32;

    address public smartWallet;
    bytes public userWalletBytecode;
    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isDeployed;

    // EIP-712 constants
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant META_TX_TYPEHASH = keccak256("MetaTransaction(address user,address target,bytes data,uint256 value,uint256 fee,uint256 nonce,uint256 chainId)");
    bytes32 public constant META_DEPLOY_TYPEHASH = keccak256("MetaDeploy(address user,uint256 nonce,uint256 chainId)");
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    string public constant NAME = "MetaWallet";
    string public constant VERSION = "12"; // Updated version

    event WalletDeployed(address indexed user, address wallet);
    event MetaTransactionExecuted(address indexed user, address target, uint256 value, bytes data, uint256 fee);
    event MetaWalletDeployed(address indexed user, address wallet);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event SmartWalletSet(address smartWallet);
    event WalletPaused(address indexed account);
    event WalletUnpaused(address indexed account);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes(NAME)),
            keccak256(bytes(VERSION)),
            block.chainid,
            address(this)
        ));
    }

    modifier onlyRelayer() {
        require(relayerWhitelist[msg.sender], "Relayer not authorized");
        _;
    }

    modifier validNonce(address user, uint256 nonce) {
        require(nonces[user] == nonce, "Invalid nonce");
        nonces[user]++;
        _;
    }

    modifier validSignature(bytes32 digest, address user, bytes memory signature) {
        require(digest.recover(signature) == user, "Invalid signature");
        _;
    }

    modifier hasSmartWallet() {
        require(smartWallet != address(0), "Smart wallet not set");
        _;
    }

    function pause() external onlyOwner {
        _pause();
        emit WalletPaused(msg.sender);
    }

    function unpause() external onlyOwner {
        _unpause();
        emit WalletUnpaused(msg.sender);
    }

    function setSmartWallet(address _smartWallet) external onlyOwner {
        require(_smartWallet != address(0), "Invalid smart wallet address");
        smartWallet = _smartWallet;
        emit SmartWalletSet(_smartWallet);
    }

    function computeWalletAddress(address user) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        return Create2.computeAddress(salt, keccak256(bytecode));
    }

    function deployWallet(address user) external onlyOwner whenNotPaused {
        require(!isDeployed[user], "Wallet already deployed");

        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));

        address wallet;
        assembly {
            wallet := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(wallet)) { revert(0, 0) }
        }

        isDeployed[user] = true;
        emit WalletDeployed(user, wallet);
    }

    function deployWalletMeta(
        address user,
        uint256 nonce,
        bytes calldata signature
    ) external onlyRelayer whenNotPaused validNonce(user, nonce) validSignature(getDeployDigest(user, nonce), user, signature) {
        require(!isDeployed[user], "Wallet already deployed");

        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));

        address wallet;
        assembly {
            wallet := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(wallet)) { revert(0, 0) }
        }

        isDeployed[user] = true;
        emit MetaWalletDeployed(user, wallet);
    }

    function executeMetaTransaction(
        address user,
        address target,
        bytes calldata data,
        uint256 value,
        uint256 fee,
        uint256 nonce,
        bytes calldata signature
    ) external payable onlyRelayer whenNotPaused validNonce(user, nonce) validSignature(getTransactionDigest(user, target, data, value, fee, nonce), user, signature) nonReentrant hasSmartWallet {
        address wallet = computeWalletAddress(user);
        require(wallet.code.length > 0, "Wallet not deployed");

        uint256 totalAmount = value + fee;
        require(msg.value >= totalAmount, "Insufficient msg.value");

        // Pay the gas fee safely
        (bool feeSent, ) = smartWallet.call{value: fee, gas: 2300}("");
        require(feeSent, "Gas fee payment failed");

        // Forward the call to the user's wallet
        (bool success, ) = wallet.call{value: value}(abi.encodeWithSignature(
            "execute(address,bytes,uint256,uint256,address)",
            target,
            data,
            value,
            fee,
            msg.sender
        ));
        require(success, "Wallet execution failed");

        emit MetaTransactionExecuted(user, target, value, data, fee);
    }

    function addRelayer(address relayer) external onlyOwner {
        require(relayer != address(0), "Invalid relayer address");
        require(!relayerWhitelist[relayer], "Relayer already added");
        relayerWhitelist[relayer] = true;
        emit RelayerAdded(relayer);
    }

    function removeRelayer(address relayer) external onlyOwner {
        require(relayerWhitelist[relayer], "Relayer not found");
        relayerWhitelist[relayer] = false;
        emit RelayerRemoved(relayer);
    }

    function getTransactionDigest(
        address user,
        address target,
        bytes memory data,
        uint256 value,
        uint256 fee,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                user,
                target,
                keccak256(data),
                value,
                fee,
                nonce,
                block.chainid
            ))
        ));
    }

    function getDeployDigest(address user, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                META_DEPLOY_TYPEHASH,
                user,
                nonce,
                block.chainid
            ))
        ));
    }
}