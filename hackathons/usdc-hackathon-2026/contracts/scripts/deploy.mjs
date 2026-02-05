import { readFileSync } from 'fs';
import { resolve } from 'path';
import { JsonRpcProvider, Wallet, ContractFactory, getBytes, keccak256, toUtf8Bytes } from 'ethers';

const rpc = 'https://sepolia.base.org';
const usdc = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

const deployerKey = process.env.DEPLOYER_KEY;
if (!deployerKey) {
  console.error('Missing DEPLOYER_KEY');
  process.exit(1);
}

const abi = [
  'constructor(address usdc, address initialOwner, address initialSettler)',
  'function registerIntent(bytes32 intentIdHash, bytes32 buyerDidHash, uint256 amountMinor, uint256 amountUsdcBase, address depositAddress, uint64 expiresAt) returns (bytes32)',
  'function markClaimed(bytes32 intentIdHash, bytes32 depositTxHash, bytes32 ledgerEventIdHash)',
  'function hashIntent(bytes32 intentIdHash, bytes32 buyerDidHash, uint256 amountMinor, uint256 amountUsdcBase, address depositAddress, uint64 expiresAt) view returns (bytes32)'
];

// Bytecode placeholder: to be replaced after compilation
const bytecodePath = resolve('out/ClawDepositIntentRegistry.bin');
const bytecode = readFileSync(bytecodePath, 'utf8').trim();

const provider = new JsonRpcProvider(rpc);
const wallet = new Wallet(deployerKey, provider);

const factory = new ContractFactory(abi, bytecode, wallet);

console.log('Deploying...');
const contract = await factory.deploy(usdc, wallet.address, wallet.address);
await contract.waitForDeployment();
console.log('Contract address:', contract.target);

// Example intent hashes using the real deposit proof
const intentId = '14852d98-4c9a-49f4-b1cf-bc1710abd3f8';
const intentIdHash = keccak256(toUtf8Bytes(intentId));
const buyerDidHash = keccak256(toUtf8Bytes('did:key:deposit-demo'));

const amountMinor = 500n;
const amountUsdcBase = 5_000_000n;
const depositAddress = '0xe6Fb9eaE850a01B4FbFa186449793Bccf3cbDB10';
const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 3600);

console.log('registerIntent...');
const tx1 = await contract.registerIntent(intentIdHash, buyerDidHash, amountMinor, amountUsdcBase, depositAddress, expiresAt);
console.log('registerIntent tx:', tx1.hash);
await tx1.wait();

const depositTxHash = '0x8c6c2ddbdca1bedecd89d153fb5d42f3742edff4f63f5ecf81f3b4360ab554f0';
const ledgerEventIdHash = keccak256(toUtf8Bytes('019a05f6-a723-4b53-b4eb-8be6a6d507dc'));

console.log('markClaimed...');
const tx2 = await contract.markClaimed(intentIdHash, depositTxHash, ledgerEventIdHash);
console.log('markClaimed tx:', tx2.hash);
await tx2.wait();
