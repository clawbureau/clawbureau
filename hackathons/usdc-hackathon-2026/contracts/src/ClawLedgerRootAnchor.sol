// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal on-chain anchor for ledger Merkle roots (testnet-only).
/// @dev Emits audit checkpoints; does NOT custody funds.
contract ClawLedgerRootAnchor {
    error NotOwner();
    error WrongChain(uint256 got, uint256 expected);

    uint256 public constant EXPECTED_CHAIN_ID = 84532; // Base Sepolia

    address public owner;

    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    event RootAnchored(
        bytes32 indexed root,
        uint64 fromTs,
        uint64 toTs,
        uint32 count,
        address indexed anchor
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address initialOwner) {
        if (block.chainid != EXPECTED_CHAIN_ID) revert WrongChain(block.chainid, EXPECTED_CHAIN_ID);
        owner = initialOwner;
    }

    function setOwner(address newOwner) external onlyOwner {
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }

    function anchorRoot(bytes32 root, uint64 fromTs, uint64 toTs, uint32 count) external onlyOwner {
        emit RootAnchored(root, fromTs, toTs, count, msg.sender);
    }

    receive() external payable { revert("NO_ETH"); }
    fallback() external payable { revert("NO_FALLBACK"); }
}
