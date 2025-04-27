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

    // Konfigurasi kontrak
    address public smartWallet;
    bytes public userWalletBytecode;
    
    // Pemetaan status
    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isDeployed;

    // Konstanta EIP-712
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant META_TX_TYPEHASH = keccak256(
        "MetaTransaction(address user,address target,bytes data,uint256 value,uint256 fee,uint256 nonce,uint256 chainId)"
    );
    bytes32 public constant META_DEPLOY_TYPEHASH = keccak256(
        "MetaDeploy(address user,uint256 nonce,uint256 chainId)"
    );
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    string public constant NAME = "MetaWallet";
    string public constant VERSION = "12";

    // Event
    event WalletDeployed(address indexed user, address wallet);
    event MetaTransactionExecuted(address indexed user, address target, uint256 value, bytes data, uint256 fee);
    event MetaWalletDeployed(address indexed user, address wallet);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);
    event SmartWalletSet(address smartWallet);
    event WalletPaused(address indexed account);
    event WalletUnpaused(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() Ownable(0x484ee82f48bcaf15927c06432f4c279ee3f95d46) {
        // Inisialisasi EIP-712 Domain Separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
        
        emit OwnershipTransferred(address(0), 0x484ee82f48bcaf15927c06432f4c279ee3f95d46);
    }

    // Modifier
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

    // Fungsi Manajemen
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

    // Fungsi Wallet
    function computeWalletAddress(address user) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        return Create2.computeAddress(salt, keccak256(bytecode));
    }

    function deployWallet(address user) external onlyOwner whenNotPaused {
        require(!isDeployed[user], "Wallet already deployed");
        _deployWallet(user);
        emit WalletDeployed(user, computeWalletAddress(user));
    }

    function deployWalletMeta(
        address user,
        uint256 nonce,
        bytes calldata signature
    ) external onlyRelayer whenNotPaused validNonce(user, nonce) validSignature(getDeployDigest(user, nonce), user, signature) {
        require(!isDeployed[user], "Wallet already deployed");
        _deployWallet(user);
        emit MetaWalletDeployed(user, computeWalletAddress(user));
    }

    function _deployWallet(address user) private {
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));

        address wallet;
        assembly {
            wallet := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(wallet)) { revert(0, 0) }
        }

        isDeployed[user] = true;
    }

    // Fungsi Meta Transaction
    function executeMetaTransaction(
        address user,
        address target,
        bytes calldata data,
        uint256 value,
        uint256 fee,
        uint256 nonce,
        bytes calldata signature
    ) external payable onlyRelayer whenNotPaused validNonce(user, nonce) 
      validSignature(getTransactionDigest(user, target, data, value, fee, nonce), user, signature) 
      nonReentrant hasSmartWallet {
        
        address wallet = computeWalletAddress(user);
        require(wallet.code.length > 0, "Wallet not deployed");
        require(msg.value >= value + fee, "Insufficient msg.value");

        // Transfer fee ke smartWallet
        (bool feeSent, ) = smartWallet.call{value: fee}("");
        require(feeSent, "Fee transfer failed");

        // Eksekusi transaksi
        (bool success, ) = wallet.call{value: value}(
            abi.encodeWithSignature(
                "execute(address,bytes,uint256,uint256,address)",
                target,
                data,
                value,
                fee,
                msg.sender
            )
        );
        require(success, "Execution failed");

        emit MetaTransactionExecuted(user, target, value, data, fee);
    }

    // Fungsi Manajemen Relayer
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

    // Fungsi EIP-712
    function getTransactionDigest(
        address user,
        address target,
        bytes memory data,
        uint256 value,
        uint256 fee,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
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
                        nonce,
                        block.chainid
                    )
                )
            )
        );
    }

    function getDeployDigest(address user, uint256 nonce) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        META_DEPLOY_TYPEHASH,
                        user,
                        nonce,
                        block.chainid
                    )
                )
            )
        );
    }

    // Fungsi tambahan untuk menerima pembayaran native token
    receive() external payable {}
}