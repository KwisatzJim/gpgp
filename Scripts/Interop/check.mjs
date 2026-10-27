import * as pgp from 'openpgp';
import { mkdtemp, writeFile, readFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const folder = await mkdtemp(join(tmpdir(), 'gpgp-interop-'));
await chmod(folder, 0o700);
const crlf = text => text.replace(/\r?\n/g, '\r\n');
const headers = 'From: Interop Sender <interop@example.invalid>\r\nTo: interop@example.invalid\r\nSubject: Independent implementation fixture\r\nMIME-Version: 1.0\r\n';
const content = 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nIndependent OpenPGP fixture: caf=C3=A9.\r\nSecond line.\r\n';
const bytes = Buffer.from(content);
try {
  const generated = await pgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Interop Sender', email: 'interop@example.invalid' }], keyExpirationTime: 86400,
    config: { preferredHashAlgorithm: pgp.enums.hash.sha256, aeadProtect: false } });
  const privateKey = await pgp.readPrivateKey({ armoredKey: generated.privateKey });
  const publicKey = await pgp.readKey({ armoredKey: generated.publicKey });
  const fingerprint = publicKey.getFingerprint().toUpperCase();
  await writeFile(join(folder, 'private.asc'), generated.privateKey, { mode: 0o600 });
  await writeFile(join(folder, 'fingerprint'), fingerprint);
  await writeFile(join(folder, 'content.mime'), bytes);
  const signature = await pgp.sign({ message: await pgp.createMessage({ binary: bytes }), signingKeys: privateKey,
    detached: true, config: { preferredHashAlgorithm: pgp.enums.hash.sha256 } });
  const signaturePacket = await pgp.readSignature({ armoredSignature: signature });
  const hashNames = { 8: "pgp-sha256", 9: "pgp-sha384", 10: "pgp-sha512" };
  const hashName = hashNames[signaturePacket.packets[0].hashAlgorithm];
  assert.ok(hashName, "Fixture digest must be SHA-256, SHA-384, or SHA-512");
  const signed = headers + 'Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg=' + hashName + '; boundary="interop_signed"\r\n\r\n' +
    '--interop_signed\r\n' + content + '\r\n--interop_signed\r\nContent-Type: application/pgp-signature\r\n\r\n' + crlf(signature) + '\r\n--interop_signed--\r\n';
  await writeFile(join(folder, 'incoming-signed.eml'), signed);
  const ciphertext = await pgp.encrypt({ message: await pgp.createMessage({ binary: bytes }), encryptionKeys: publicKey,
    config: { aeadProtect: false } });
  await writeFile(join(folder, 'incoming-encrypted.eml'), headers + 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="interop_encrypted"\r\n\r\n' +
    '--interop_encrypted\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--interop_encrypted\r\nContent-Type: application/octet-stream\r\n\r\n' + crlf(ciphertext) + '\r\n--interop_encrypted--\r\n');
  const swift = spawnSync('swift', ['test', '--scratch-path', join(tmpdir(), 'gpgp-interop-swift'), '--filter', 'IndependentImplementationTests'],
    { cwd: root, env: { ...process.env, GPGP_INTEROP_DIR: folder }, encoding: 'utf8', timeout: 180000 });
  if (swift.status !== 0) throw new Error('Swift interoperability checks failed:\n' + swift.stdout + swift.stderr);
  console.log(swift.stdout.split('\n').filter(line => /passed|Executed/.test(line)).join('\n'));
  const emitted = await readFile(join(folder, 'outgoing-signed.eml'), 'utf8');
  const boundary = emitted.match(/boundary="([^"]+)"/)[1];
  const start = emitted.indexOf('--' + boundary + '\r\n') + boundary.length + 4;
  const next = emitted.indexOf('\r\n--' + boundary + '\r\n', start);
  assert.ok(next > start);
  const signedContent = Buffer.from(emitted.slice(start, next));
  assert.deepEqual(signedContent, bytes);
  const signatureArmor = emitted.slice(emitted.indexOf('-----BEGIN PGP SIGNATURE-----'), emitted.indexOf('-----END PGP SIGNATURE-----') + 27);
  const verified = await pgp.verify({ message: await pgp.createMessage({ binary: signedContent }),
    signature: await pgp.readSignature({ armoredSignature: signatureArmor }), verificationKeys: publicKey });
  assert.equal(verified.signatures.length, 1);
  await verified.signatures[0].verified;
  const encrypted = await readFile(join(folder, 'outgoing-encrypted.eml'), 'utf8');
  const armor = encrypted.slice(encrypted.indexOf('-----BEGIN PGP MESSAGE-----'), encrypted.indexOf('-----END PGP MESSAGE-----') + 25);
  const decrypted = await pgp.decrypt({ message: await pgp.readMessage({ armoredMessage: armor }), decryptionKeys: privateKey, format: 'binary' });
  assert.deepEqual(Buffer.from(decrypted.data), bytes);
  console.log('PASS: OpenPGP.js verified GPGP’s detached signature and decrypted its ciphertext, preserving exact MIME bytes.');
  console.log('PASS: GPGP verified and decrypted independent OpenPGP.js messages. No mail sent; no personal keys accessed.');
} finally {
  await rm(folder, { recursive: true, force: true });
}
