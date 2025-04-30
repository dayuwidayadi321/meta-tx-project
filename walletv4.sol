// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/UserOperation.sol";

/**
 * @title AdvancedSmartWallet - EIP-4337 Smart Wallet (v4.0) Created By DFXC INDONESIAN WEB3 PROJECT
 * @notice Smart wallet dengan multi-owner, session keys, social recovery, dan bundler support.
 * @dev Revisi: Fix semua issue keamanan dan optimasi gas
 */
contract AdvancedSmartWallet is IERC1271, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using ECDSA for bytes32;

    string public constant VERSION = "4.0";
    string public name;

    // EntryPoint EIP-4337
    IEntryPoint public immutable entryPoint;

    // Owner management
    mapping(address => bool) public owners;
    uint256 public ownerCount;

    // Recovery system (Guardian-based)
    struct RecoveryConfig {
        address[] guardians;
        mapping(address => bool) isGuardian; // Optimasi lookup
        uint256 threshold;
        uint256 delay;
        uint256 initiatedAt;
    }
    RecoveryConfig public recoveryConfig;

    // Session keys (limited-time permissions)
    struct SessionKey {
        address key;
        uint48 validUntil;
        bytes4[] allowedFunctions;
        mapping(bytes4 => bool) isAllowedFunction; // Optimasi lookup
    }
    mapping(address => SessionKey) public sessionKeys;

    // Constants
    uint256 public constant EXECUTE_GAS_LIMIT = 1_000_000;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    // Events
    event WalletInitialized(address[] indexed owners, string name);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ExecutionSuccess(address indexed target, uint256 value, bytes data);
    event ExecutionFailure(address indexed target, uint256 value, bytes data);
    event RecoveryInitiated(address indexed by, uint256 timestamp);
    event RecoveryCancelled();
    event RecoveryCompleted(address[] newOwners, address[] newGuardians);
    event SessionKeyAdded(address indexed key, uint48 validUntil, bytes4[] allowedFunctions);
    event SessionKeyRevoked(address indexed key);
    event DepositReceived(address indexed sender, uint256 amount);
    event DepositWithdrawn(address indexed to, uint256 amount);

    // Modifiers
    modifier onlyOwner() {
        require(owners[msg.sender], "AdvancedSmartWallet: caller is not owner");
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "AdvancedSmartWallet: not from EntryPoint");
        _;
    }

    modifier onlyRecovery() {
        require(
            recoveryConfig.initiatedAt > 0 &&
            block.timestamp >= recoveryConfig.initiatedAt + recoveryConfig.delay,
            "AdvancedSmartWallet: recovery not ready"
        );
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    function initialize(
        address[] calldata _owners,
        string calldata _name,
        address[] calldata _guardians,
        uint256 _recoveryThreshold,
        uint256 _recoveryDelay
    ) external initializer {
        require(_owners.length > 0, "AdvancedSmartWallet: no owners");
        require(_recoveryThreshold > 0 && _recoveryThreshold <= _guardians.length, "Invalid threshold");
        require(_recoveryDelay <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        name = _name;
        recoveryConfig.threshold = _recoveryThreshold;
        recoveryConfig.delay = _recoveryDelay;
        recoveryConfig.initiatedAt = 0;

        // Set owners dengan pengecekan duplikat
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            require(!owners[owner], "AdvancedSmartWallet: duplicate owner");
            owners[owner] = true;
        }
        ownerCount = _owners.length;

        // Set guardians
        recoveryConfig.guardians = _guardians;
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "AdvancedSmartWallet: invalid guardian");
            recoveryConfig.isGuardian[_guardians[i]] = true;
        }

        emit WalletInitialized(_owners, _name);
    }

    // ========== EIP-4337 & Bundler Functions ========== //
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        if (!_validateSignature(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (missingWalletFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingWalletFunds}("");
            require(success, "Failed to refund gas");
        }

        return 0;
    }

    // ========== Owner Management ========== //
    function addOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AdvancedSmartWallet: invalid owner");
        require(!owners[newOwner], "AdvancedSmartWallet: already owner");

        owners[newOwner] = true;
        ownerCount++;
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address ownerToRemove) external onlyOwner {
        require(owners[ownerToRemove], "AdvancedSmartWallet: not owner");
        require(ownerCount > 1, "AdvancedSmartWallet: cannot remove last owner");

        owners[ownerToRemove] = false;
        ownerCount--;
        emit OwnerRemoved(ownerToRemove);
    }

    // ========== Recovery System ========== //
    function initiateRecovery() external {
        require(recoveryConfig.isGuardian[msg.sender], "AdvancedSmartWallet: not guardian");
        recoveryConfig.initiatedAt = block.timestamp;
        emit RecoveryInitiated(msg.sender, block.timestamp);
    }

    function cancelRecovery() external onlyOwner {
        recoveryConfig.initiatedAt = 0;
        emit RecoveryCancelled();
    }

    function completeRecovery(address[] calldata newOwners, address[] calldata newGuardians) external onlyRecovery {
        require(newOwners.length > 0, "AdvancedSmartWallet: no new owners");
        require(newGuardians.length >= recoveryConfig.threshold, "Insufficient guardians");

        // Reset owners
        for (uint256 i = 0; i < ownerCount; i++) {
            owners[recoveryConfig.guardians[i]] = false;
        }

        // Set new owners
        for (uint256 i = 0; i < newOwners.length; i++) {
            address owner = newOwners[i];
            require(owner != address(0), "AdvancedSmartWallet: invalid owner");
            owners[owner] = true;
        }
        ownerCount = newOwners.length;

        // Update guardians
        delete recoveryConfig.guardians;
        for (uint256 i = 0; i < newGuardians.length; i++) {
            address guardian = newGuardians[i];
            require(guardian != address(0), "AdvancedSmartWallet: invalid guardian");
            recoveryConfig.guardians.push(guardian);
            recoveryConfig.isGuardian[guardian] = true;
        }

        recoveryConfig.initiatedAt = 0;
        emit RecoveryCompleted(newOwners, newGuardians);
    }

    // ========== Session Keys ========== //
    function addSessionKey(
        address _key,
        uint48 _validUntil,
        bytes4[] calldata _allowedFunctions
    ) external onlyOwner {
        require(_key != address(0), "Invalid session key");
        require(_validUntil > block.timestamp, "Expiration must be in future");

        SessionKey storage session = sessionKeys[_key];
        session.key = _key;
        session.validUntil = _validUntil;
        
        for (uint256 i = 0; i < _allowedFunctions.length; i++) {
            session.allowedFunctions.push(_allowedFunctions[i]);
            session.isAllowedFunction[_allowedFunctions[i]] = true;
        }

        emit SessionKeyAdded(_key, _validUntil, _allowedFunctions);
    }

    function revokeSessionKey(address _key) external onlyOwner {
        require(sessionKeys[_key].key != address(0), "Session key not found");
        delete sessionKeys[_key];
        emit SessionKeyRevoked(_key);
    }

    // ========== Internal Functions ========== //
    function _validateSignature(bytes32 hash, bytes memory signature) internal view returns (bool) {
        address recovered = hash.recover(signature);
        return owners[recovered] || _isValidSessionKey(recovered, hash);
    }

    // ========== Valid Session Key ========== //
    function _isValidSessionKey(address key, bytes32 hash) internal view returns (bool) {
        SessionKey storage session = sessionKeys[key];
        return session.key != address(0) 
            && block.timestamp <= session.validUntil
            && session.isAllowedFunction[bytes4(hash)];
    }
    
    // ========== ERC1271 Implementation ========== //
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        if (_validateSignature(hash, signature)) {
            return IERC1271.isValidSignature.selector;
        } else {
            return bytes4(0);
        }
    }

    // ========== Upgrade & Fallback ========== //
    function _authorizeUpgrade(address) internal override onlyOwner {}

    receive() external payable {
        emit DepositReceived(msg.sender, msg.value);
    }

    // ========== Deposit Management ========== //
    function addDeposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
        emit DepositReceived(msg.sender, msg.value);
    }

    function withdrawDeposit(address payable withdrawAddress, uint256 amount) external onlyOwner nonReentrant {
        entryPoint.withdrawTo(withdrawAddress, amount);
        emit DepositWithdrawn(withdrawAddress, amount);
    }
}

/**
 * @title AdvancedSmartWalletFactory v4.0
 * @dev Factory untuk deploy AdvancedSmartWallet dengan proxy UUPS
 */
contract AdvancedSmartWalletFactory {
    string public constant VERSION = "4.0";
    string public constant NAME = "AdvancedSmartWalletFactory";

    IEntryPoint public immutable entryPoint;
    address public immutable walletImplementation;

    mapping(address => address[]) private _userWallets;
    mapping(address => bool) public isWalletDeployed;

    event WalletCreated(address indexed wallet, address[] owners, string name);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        walletImplementation = address(new AdvancedSmartWallet(_entryPoint));
    }

    function deployWallet(
        address[] calldata owners,
        string calldata name,
        address[] calldata guardians,
        uint256 recoveryThreshold,
        uint256 recoveryDelay
    ) external returns (address wallet) {
        bytes memory initData = abi.encodeWithSelector(
            AdvancedSmartWallet.initialize.selector,
            owners,
            name,
            guardians,
            recoveryThreshold,
            recoveryDelay
        );

        wallet = address(new ERC1967Proxy(walletImplementation, initData));

        for (uint256 i = 0; i < owners.length; i++) {
            _userWallets[owners[i]].push(wallet);
        }

        isWalletDeployed[wallet] = true;
        emit WalletCreated(wallet, owners, name);
    }

    function getWallets(address user) external view returns (address[] memory) {
        return _userWallets[user];
    }
}
