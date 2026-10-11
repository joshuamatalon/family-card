// Encrypts private/ into docs/. Plain card content never enters docs/ or git.
// Usage: node build.mjs   (reads the passphrase from private/pass.txt, creating one if missing)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const ITER = 150000;
const passFile = 'private/pass.txt';
if (!existsSync(passFile)) {
  const abc = 'abcdefghjkmnpqrstuvwxyz23456789';
  const pick = [...crypto.getRandomValues(new Uint8Array(16))].map(b => abc[b % abc.length]).join('');
  writeFileSync(passFile, pick);
}
const pass = readFileSync(passFile, 'utf8').trim();
const salt = crypto.getRandomValues(new Uint8Array(16));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

async function seal(src, dst) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, readFileSync(src)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv); out.set(ct, iv.length);
  writeFileSync(dst, out);
  console.log(dst, out.length);
}

await seal('private/card.json', 'docs/card.enc');
for (const n of ['p1', 'p2', 'p3']) await seal(`private/${n}.jpg`, `docs/${n}.enc`);
writeFileSync('docs/meta.json', JSON.stringify({ salt: Buffer.from(salt).toString('base64'), iter: ITER }));
console.log('passphrase:', pass);
