import fs from 'fs';
import path from 'path';
import solc from 'solc';

const srcDir = path.resolve('src');
const outDir = path.resolve('out');

const sources = {};
for (const file of fs.readdirSync(srcDir)) {
  if (!file.endsWith('.sol')) continue;
  const filePath = path.join(srcDir, file);
  sources[file] = { content: fs.readFileSync(filePath, 'utf8') };
}

const input = {
  language: 'Solidity',
  sources,
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

fs.mkdirSync(outDir, { recursive: true });

for (const contracts of Object.values(output.contracts)) {
  for (const [contractName, contract] of Object.entries(contracts)) {
    const binPath = path.join(outDir, `${contractName}.bin`);
    const abiPath = path.join(outDir, `${contractName}.abi.json`);

    fs.writeFileSync(binPath, contract.evm.bytecode.object);
    fs.writeFileSync(abiPath, JSON.stringify(contract.abi, null, 2));
    console.log('Compiled:', binPath);
  }
}
