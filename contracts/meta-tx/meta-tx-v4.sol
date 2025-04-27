// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaTransactionWalletBatch is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using ECDSA for bytes32;

    // Events
    event Deposited(address indexed sender, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);
    event MetaTransactionExecuted(address indexed user, address target, bytes data, uint256 nonce);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);

    mapping(address => uint256) public nonces;
    mapping(address => bool) public relayers;

    bytes32 public DOMAIN_SEPARATOR;

    bytes32 public constant META_BATCH_TYPEHASH = keccak256(
        "MetaBatch(address from,address[] to,bytes[] data,uint256 nonce,uint256 chainId)"
    );

    modifier onlyRelayer() {
        require(relayers[msg.sender], "Not a relayer");
        _;
    }

    modifier onlyOwnerOrSelf() {
        require(msg.sender == owner() || msg.sender == address(this), "Not authorized");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();

        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("MetaTransactionWalletBatch")),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    fallback() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    function withdrawAll(address payable to) external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No balance");
        (bool success, ) = to.call{value: balance}("");
        require(success, "Withdraw failed");
        emit Withdrawn(to, balance);
    }

    function addRelayer(address newRelayer) external onlyOwner {
        require(!relayers[newRelayer], "Already a relayer");
        relayers[newRelayer] = true;
        emit RelayerAdded(newRelayer);
    }

    function removeRelayer(address relayer) external onlyOwner {
        require(relayers[relayer], "Not a relayer");
        relayers[relayer] = false;
        emit RelayerRemoved(relayer);
    }

    function executeMetaBatchWithSignature(
        address from,
        address[] calldata targets,
        bytes[] calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external payable returns (bytes[] memory) {
        require(targets.length == data.length, "Mismatched targets and data");
        require(nonce == nonces[from], "Invalid nonce");

        bytes32 structHash = keccak256(
            abi.encode(
                META_BATCH_TYPEHASH,
                from,
                _hashTargets(targets),
                _hashData(data),
                nonce,
                block.chainid
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = digest.recover(signature);
        require(signer == from, "Invalid signature");

        nonces[from] += 1;

        bytes[] memory results = new bytes[](targets.length);
        uint256 gasBefore = gasleft();

        for (uint256 i = 0; i < targets.length; i++) {
            results[i] = _executeSingleMetaTransaction(targets[i], data[i], from, nonce);
        }

        uint256 gasUsed = gasBefore - gasleft();
        uint256 relayerFee = gasUsed * tx.gasprice;
        require(msg.value >= relayerFee, "Insufficient gas fee paid");

        return results;
    }

    function _executeSingleMetaTransaction(
        address target,
        bytes calldata data,
        address from,
        uint256 nonce
    ) internal returns (bytes memory) {
        require(target != address(0), "Invalid target address");

        (bool success, bytes memory returnData) = target.call{value: 0}(data);
        require(success, "Meta-transaction failed");

        emit MetaTransactionExecuted(from, target, data, nonce);

        return returnData;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function _hashTargets(address[] calldata targets) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i = 0; i < targets.length; i++) {
            packed = bytes.concat(packed, abi.encodePacked(targets[i]));
        }
        return keccak256(packed);
    }

    function _hashData(bytes[] calldata data) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i = 0; i < data.length; i++) {
            packed = bytes.concat(packed, keccak256(data[i]));
        }
        return keccak256(packed);
    }
}