# Claw Bureau Smart Contracts

## ClawsigRTAnchor

Receipt Transparency Merkle Root anchoring contract. Prevents insider
manipulation of the append-only RT log by committing daily Merkle roots to
an immutable L2 ledger. Red Team Fix #3 (Insider Threat / Log Manipulation).

### Design

- **Chain:** Base (Sepolia for testnet, Mainnet for production)
- **Oracle signer:** Claw Bureau operational wallet (ECDSA)
- **Epochs:** UNIX day number (`Math.floor(timestamp / 86400)`)
- **Monotonic:** Each epoch must be strictly greater than the previous
- **Immutable:** Once an epoch root is anchored it cannot be overwritten

### How it works

1. Every day at 00:00 UTC a Cloudflare Cron worker in `services/clawlogs`
   reads the current RT Merkle root via `GET /v1/rt/root`.
2. It signs `keccak256(abi.encodePacked(epoch, rootHash, treeSize))` with
   the oracle ECDSA key (Ethereum personal-sign prefix applied on-chain).
3. It calls `anchorRoot(epoch, rootHash, treeSize, sig)` on the Base contract.
4. The contract verifies the signature, checks monotonicity, stores the root,
   and emits `RootAnchored(epoch, rootHash, treeSize)`.

### Verification

Anyone can verify any historical root on-chain:

```solidity
bytes32 root = anchor.verifyRoot(epochNumber);
// root == bytes32(0) means that epoch has not been anchored yet
```

Or via Base block explorer / ethers.js:

```typescript
const root = await contract.verifyRoot(20490); // UNIX day 20490
```

### Deployment

```bash
# Testnet (Base Sepolia)
forge create contracts/ClawsigRTAnchor.sol:ClawsigRTAnchor \
  --rpc-url https://sepolia.base.org \
  --private-key $DEPLOYER_KEY \
  --constructor-args $ORACLE_ADDRESS

# Production (Base Mainnet)
forge create contracts/ClawsigRTAnchor.sol:ClawsigRTAnchor \
  --rpc-url https://mainnet.base.org \
  --private-key $DEPLOYER_KEY \
  --constructor-args $ORACLE_ADDRESS
```

### Secrets

- `ORACLE_ECDSA_KEY` — private key for signing anchor messages
  (store at `~/.clawsecrets/clawlogs/ORACLE_ECDSA_KEY.staging` / `.prod`)
- `RT_ANCHOR_CONTRACT` — deployed contract address
  (store at `~/.clawsecrets/clawlogs/RT_ANCHOR_CONTRACT.staging` / `.prod`)
- `BASE_RPC_URL` — Base JSON-RPC endpoint
  (store at `~/.clawsecrets/clawlogs/BASE_RPC_URL.staging` / `.prod`)
