import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const artifact = resolve(process.argv[2] ?? 'pkg/zinc_core_bg.wasm');
const module = new WebAssembly.Module(readFileSync(artifact));
const exports = WebAssembly.Module.exports(module).map((entry) => entry.name);

for (const forbidden of [
  'generate_wallet',
  'encrypt_wallet',
  'decrypt_wallet',
  'encrypt_secret',
  'decrypt_secret',
  'zincwasmwallet_new_encrypted',
]) {
  if (exports.includes(forbidden)) {
    throw new Error(`production zinc-core WASM must not export ${forbidden}`);
  }
}

console.log('zinc-core WASM export audit passed');
