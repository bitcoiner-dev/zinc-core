import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const artifact = resolve(process.argv[2] ?? 'pkg/zinc_core_bg.wasm');
const module = new WebAssembly.Module(readFileSync(artifact));
const exports = WebAssembly.Module.exports(module).map((entry) => entry.name);

if (exports.includes('generate_wallet')) {
  throw new Error('production zinc-core WASM must not export generate_wallet');
}

console.log('zinc-core WASM export audit passed');
