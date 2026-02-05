import fs from 'fs';
import path from 'path';
import solc from 'solc';

const srcPath = path.resolve('src/ClawDepositIntentRegistry.sol');
const source = fs.readFileSync(srcPath, 'utf8');

const input = {
  language: 'Solidity',
  sources: {
    'ClawDepositIntentRegistry.sol': { content: source }
  },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode']
      }
    }
  }
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));
if (output.errors) {
  const errors = output.errors.filter(e => e.severity === 'error');
  output.errors.forEach(e => console.error(e.formattedMessage));
  if (errors.length) {
    process.exit(1);
  }
}

const contract = output.contracts['ClawDepositIntentRegistry.sol']['ClawDepositIntentRegistry'];
const outDir = path.resolve('out');
fs.mkdirSync(outDir, { recursive: true });

fs.writeFileSync(path.join(outDir, 'ClawDepositIntentRegistry.bin'), contract.evm.bytecode.object);
fs.writeFileSync(path.join(outDir, 'ClawDepositIntentRegistry.abi.json'), JSON.stringify(contract.abi, null, 2));

console.log('Compiled:', path.join(outDir, 'ClawDepositIntentRegistry.bin'));
