// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Non-custodial registry for USDC deposit intents + claim bindings (testnet-only).
/// @dev Stores commitments + emits events. Does NOT receive tokens. NOT an escrow.
contract ClawDepositIntentRegistry {
    // ---- Errors ----
    error NotOwner();
    error NotSettler();
    error WrongChain(uint256 got, uint256 expected);
    error WrongUSDC(address got, address expected);
    error IntentAlreadyExists(bytes32 intentIdHash);
    error IntentNotFound(bytes32 intentIdHash);
    error IntentExpired(uint64 nowTs, uint64 expiresAt);
    error IntentCanceled(bytes32 intentIdHash);
    error IntentAlreadyClaimed(bytes32 intentIdHash);

    // ---- Events ----
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    event SettlerUpdated(address indexed oldSettler, address indexed newSettler);

    event IntentRegistered(
        bytes32 indexed intentIdHash,
        bytes32 indexed intentHash,
        address indexed registrant,
        bytes32 buyerDidHash,
        uint256 amountMinor,        // USD cents
        uint256 amountUsdcBase,     // USDC base units (6 decimals on Base Sepolia)
        address usdc,
        address depositAddress,
        uint64  expiresAt
    );

    event IntentCanceledEvent(bytes32 indexed intentIdHash, address indexed by);

    event IntentClaimed(
        bytes32 indexed intentIdHash,
        bytes32 indexed intentHash,
        bytes32 indexed depositTxHash,
        address settler,
        bytes32 ledgerEventIdHash
    );

    // ---- Config (testnet-only) ----
    uint256 public constant EXPECTED_CHAIN_ID = 84532; // Base Sepolia
    address public immutable USDC; // Base Sepolia USDC

    address public owner;
    address public settler; // authorized to post claims

    struct Intent {
        address registrant;
        bytes32 buyerDidHash;
        uint256 amountMinor;
        uint256 amountUsdcBase;
        address depositAddress;
        uint64 expiresAt;
        bool canceled;
        bool claimed;
        bytes32 intentHash;
        bytes32 depositTxHash;
        bytes32 ledgerEventIdHash;
    }

    mapping(bytes32 => Intent) public intents;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlySettler() {
        if (msg.sender != settler) revert NotSettler();
        _;
    }

    constructor(address usdc, address initialOwner, address initialSettler) {
        if (block.chainid != EXPECTED_CHAIN_ID) revert WrongChain(block.chainid, EXPECTED_CHAIN_ID);
        address expected = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;
        if (usdc != expected) revert WrongUSDC(usdc, expected);

        USDC = usdc;
        owner = initialOwner;
        settler = initialSettler;
    }

    function setOwner(address newOwner) external onlyOwner {
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }

    function setSettler(address newSettler) external onlyOwner {
        emit SettlerUpdated(settler, newSettler);
        settler = newSettler;
    }

    function hashIntent(
        bytes32 intentIdHash,
        bytes32 buyerDidHash,
        uint256 amountMinor,
        uint256 amountUsdcBase,
        address depositAddress,
        uint64 expiresAt
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            EXPECTED_CHAIN_ID,
            USDC,
            intentIdHash,
            buyerDidHash,
            amountMinor,
            amountUsdcBase,
            depositAddress,
            expiresAt
        ));
    }

    function registerIntent(
        bytes32 intentIdHash,
        bytes32 buyerDidHash,
        uint256 amountMinor,
        uint256 amountUsdcBase,
        address depositAddress,
        uint64 expiresAt
    ) external returns (bytes32 intentHash) {
        if (block.timestamp > expiresAt) revert IntentExpired(uint64(block.timestamp), expiresAt);

        Intent storage it = intents[intentIdHash];
        if (it.registrant != address(0)) revert IntentAlreadyExists(intentIdHash);

        intentHash = hashIntent(intentIdHash, buyerDidHash, amountMinor, amountUsdcBase, depositAddress, expiresAt);

        intents[intentIdHash] = Intent({
            registrant: msg.sender,
            buyerDidHash: buyerDidHash,
            amountMinor: amountMinor,
            amountUsdcBase: amountUsdcBase,
            depositAddress: depositAddress,
            expiresAt: expiresAt,
            canceled: false,
            claimed: false,
            intentHash: intentHash,
            depositTxHash: bytes32(0),
            ledgerEventIdHash: bytes32(0)
        });

        emit IntentRegistered(
            intentIdHash,
            intentHash,
            msg.sender,
            buyerDidHash,
            amountMinor,
            amountUsdcBase,
            USDC,
            depositAddress,
            expiresAt
        );
    }

    function cancelIntent(bytes32 intentIdHash) external {
        Intent storage it = intents[intentIdHash];
        if (it.registrant == address(0)) revert IntentNotFound(intentIdHash);
        if (msg.sender != it.registrant) revert NotOwner();
        if (it.claimed) revert IntentAlreadyClaimed(intentIdHash);

        it.canceled = true;
        emit IntentCanceledEvent(intentIdHash, msg.sender);
    }

    function markClaimed(
        bytes32 intentIdHash,
        bytes32 depositTxHash,
        bytes32 ledgerEventIdHash
    ) external onlySettler {
        Intent storage it = intents[intentIdHash];
        if (it.registrant == address(0)) revert IntentNotFound(intentIdHash);
        if (it.canceled) revert IntentCanceled(intentIdHash);
        if (it.claimed) revert IntentAlreadyClaimed(intentIdHash);
        if (block.timestamp > it.expiresAt) revert IntentExpired(uint64(block.timestamp), it.expiresAt);

        it.claimed = true;
        it.depositTxHash = depositTxHash;
        it.ledgerEventIdHash = ledgerEventIdHash;

        emit IntentClaimed(intentIdHash, it.intentHash, depositTxHash, msg.sender, ledgerEventIdHash);
    }

    receive() external payable { revert("NO_ETH"); }
    fallback() external payable { revert("NO_FALLBACK"); }
}
