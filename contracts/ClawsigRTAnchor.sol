// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * ClawsigRTAnchor — Receipt Transparency Merkle Root Anchoring
 *
 * Red Team Fix #3: Cross-chain L2 anchoring prevents insider manipulation
 * of the append-only RT log. Daily Merkle roots are committed here so that
 * Claw Bureau cannot silently rebuild the tree without rewriting Base L2.
 *
 * Deployed to Base (Sepolia for testnet, Mainnet for prod).
 */
contract ClawsigRTAnchor {
    /// @notice Address of the oracle signer (Claw Bureau operational wallet).
    address public oracleSigner;

    /// @notice Mapping from epoch (UNIX day number) to anchored Merkle root.
    mapping(uint256 => bytes32) public dailyRoots;

    /// @notice The most recently anchored epoch (monotonically increasing).
    uint256 public latestEpoch;

    /// @notice Emitted when a new daily root is anchored.
    event RootAnchored(uint256 indexed epoch, bytes32 rootHash, uint256 treeSize);

    /// @param _oracle The address authorized to sign anchor messages.
    constructor(address _oracle) {
        require(_oracle != address(0), "Oracle address cannot be zero");
        oracleSigner = _oracle;
    }

    /**
     * @notice Anchor a daily Merkle root on-chain.
     * @param epoch     UNIX day number (block.timestamp / 86400).
     * @param rootHash  SHA-256 Merkle root of the RT log at end-of-day.
     * @param treeSize  Number of leaves in the Merkle tree at anchor time.
     * @param sig       ECDSA signature over keccak256(epoch, rootHash, treeSize).
     */
    function anchorRoot(
        uint256 epoch,
        bytes32 rootHash,
        uint256 treeSize,
        bytes memory sig
    ) external {
        bytes32 message = keccak256(abi.encodePacked(epoch, rootHash, treeSize));
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
        );

        require(
            _recoverSigner(ethHash, sig) == oracleSigner,
            "Invalid signature"
        );
        require(
            dailyRoots[epoch] == bytes32(0),
            "Epoch already anchored"
        );
        require(
            epoch > latestEpoch,
            "Epoch must be monotonically increasing"
        );

        dailyRoots[epoch] = rootHash;
        latestEpoch = epoch;

        emit RootAnchored(epoch, rootHash, treeSize);
    }

    /**
     * @notice Look up the anchored root for a given epoch.
     * @param epoch UNIX day number.
     * @return The Merkle root hash (bytes32(0) if not anchored).
     */
    function verifyRoot(uint256 epoch) external view returns (bytes32) {
        return dailyRoots[epoch];
    }

    /**
     * @dev Recover the signer address from a 65-byte ECDSA signature.
     */
    function _recoverSigner(
        bytes32 hash,
        bytes memory sig
    ) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        return ecrecover(hash, v, r, s);
    }
}
