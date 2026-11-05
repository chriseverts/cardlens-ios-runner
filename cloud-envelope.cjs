// Authenticated encryption for a public runner's source and result archives.
// Only ciphertext goes into the public repository/artifacts; keys use secrets.
const fs = require('node:fs');
const crypto = require('node:crypto');
const [mode, input, output] = process.argv.slice(2);
const key = Buffer.from(process.env.CARDLENS_BUILD_KEY || '', 'hex');
if (key.length !== 32 || !['seal', 'open'].includes(mode) || !input || !output)
  throw new Error('Expected seal/open, input, output and a 32-byte secret key.');
const data = fs.readFileSync(input);
let result;
if (mode === 'seal') {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  result = Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
} else {
  if (data.length < 28) throw new Error('Invalid encrypted envelope.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  result = Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]);
}
fs.writeFileSync(output, result, {mode: 0o600});
