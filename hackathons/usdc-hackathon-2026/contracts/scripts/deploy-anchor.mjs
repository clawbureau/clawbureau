import { readFileSync } from 'fs';
import { resolve } from 'path';
import { JsonRpcProvider, Wallet, ContractFactory } from 'ethers';

const rpc = 'https://sepolia.base.org';

const deployerKey = process.env.DEPLOYER_KEY;
if (!deployerKey) {
  console.error('Missing DEPLOYER_KEY');
  process.exit(1);
}

const abi = [
  'constructor(address initialOwner)',
  'function anchorRoot(bytes32 root, uint64 fromTs, uint64 toTs, uint32 count)',
  'function setOwner(address newOwner)'
];

const bytecodePath = resolve('out/ClawLedgerRootAnchor.bin');
const bytecode = readFileSync(bytecodePath, 'utf8').trim();

const provider = new JsonRpcProvider(rpc);
const wallet = new Wallet(deployerKey, provider);

const factory = new ContractFactory(abi, bytecode, wallet);

console.log('Deploying ClawLedgerRootAnchor...');
const contract = await factory.deploy(wallet.address);
const deployTx = contract.deploymentTransaction();
if (deployTx) {
  console.log('Deploy tx:', deployTx.hash);
}
await contract.waitForDeployment();
console.log('Anchor contract address:', contract.target);
