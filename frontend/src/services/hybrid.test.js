// =============================================================================
// services/hybrid.test.js — Unit and integration tests for AES + RSA Hybrid Encryption
// =============================================================================
const { TextEncoder: UtilTextEncoder, TextDecoder: UtilTextDecoder } = require('util');
const { webcrypto } = require('crypto');

global.TextEncoder = UtilTextEncoder;
global.TextDecoder = UtilTextDecoder;
if (!global.crypto || !global.crypto.subtle) {
  global.crypto = webcrypto;
}

import {
  generateDataKey,
  encryptWithDataKey,
  decryptWithDataKey,
  calculateSha256,
  base64ToArrayBuffer,
  arrayBufferToBase64,
} from './crypto.js';
import {
  generateRsaKeyPair,
  protectPrivateKey,
  unprotectPrivateKey,
  wrapDataKey,
  unwrapDataKey,
  hybridEncryptFile,
  hybridDecryptFile,
  verifyKeypairMatch,
} from './rsa.js';

describe('Phase 7: AES + RSA Hybrid Encryption Engine', () => {
  let keyPairAlice;
  let keyPairBob;

  beforeAll(async () => {
    keyPairAlice = await generateRsaKeyPair(2048);
    keyPairBob = await generateRsaKeyPair(2048);
  });

  // -------------------------------------------------------------------------
  // 1. Data Key Generation & AES-GCM Direct Operations
  // -------------------------------------------------------------------------
  test('generateDataKey creates a fresh 256-bit AES-GCM CryptoKey', async () => {
    const key = await generateDataKey(256);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.algorithm.length).toBe(256);
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
  });

  test('encryptWithDataKey and decryptWithDataKey roundtrip cleanly with 96-bit IV', async () => {
    const key = await generateDataKey(256);
    const plaintext = new TextEncoder().encode('Confidential cloud data payload').buffer;

    const enc = await encryptWithDataKey(plaintext, key);
    expect(enc.ciphertext).toBeDefined();
    expect(enc.iv).toBeDefined();
    expect(enc.integrity_hash).toBeDefined();
    expect(enc.algorithm).toBe('AES-GCM-256');

    // IV must be 12 bytes (96 bits)
    const ivBytes = base64ToArrayBuffer(enc.iv);
    expect(ivBytes.byteLength).toBe(12);

    const decrypted = await decryptWithDataKey(
      base64ToArrayBuffer(enc.ciphertext),
      key,
      enc.iv,
      enc.integrity_hash
    );

    const decoded = new TextDecoder().decode(decrypted);
    expect(decoded).toBe('Confidential cloud data payload');
  });

  // -------------------------------------------------------------------------
  // 2. RSA-OAEP Key Wrapping & Unwrapping
  // -------------------------------------------------------------------------
  test('wrapDataKey and unwrapDataKey roundtrip successfully using RSA-OAEP', async () => {
    const dataKey = await generateDataKey(256);

    // Alice wraps AES key with her public key
    const { wrappedKeyB64, wrappedKeyBuffer } = await wrapDataKey(dataKey, keyPairAlice.publicKey);
    expect(typeof wrappedKeyB64).toBe('string');
    expect(wrappedKeyBuffer.byteLength).toBe(256); // 2048-bit RSA = 256 bytes

    // Alice unwraps with her private key
    const unwrappedKey = await unwrapDataKey(wrappedKeyB64, keyPairAlice.privateKey);
    expect(unwrappedKey).toBeDefined();
    expect(unwrappedKey.type).toBe('secret');
    expect(unwrappedKey.algorithm.name).toBe('AES-GCM');
    expect(unwrappedKey.algorithm.length).toBe(256);

    // Verify unwrapped key actually works for encryption/decryption
    const testData = new TextEncoder().encode('Key wrapping validation test').buffer;
    const enc = await encryptWithDataKey(testData, unwrappedKey);
    const dec = await decryptWithDataKey(base64ToArrayBuffer(enc.ciphertext), dataKey, enc.iv);
    expect(new TextDecoder().decode(dec)).toBe('Key wrapping validation test');
  });

  test('unwrapDataKey rejects unwrapping when attempted with wrong private key', async () => {
    const dataKey = await generateDataKey(256);

    // Key wrapped with Alice's public key
    const { wrappedKeyB64 } = await wrapDataKey(dataKey, keyPairAlice.publicKey);

    // Bob attempts to unwrap Alice's wrapped key with his private key -> MUST REJECT
    await expect(
      unwrapDataKey(wrappedKeyB64, keyPairBob.privateKey)
    ).rejects.toThrow(/Key unwrapping failed/i);
  });

  test('unwrapDataKey rejects corrupted/tampered wrapped key payload', async () => {
    const dataKey = await generateDataKey(256);
    const { wrappedKeyB64 } = await wrapDataKey(dataKey, keyPairAlice.publicKey);

    // Flip bits in the base64 wrapped key
    const tampered = wrappedKeyB64.slice(0, 10) + 'XXXX' + wrappedKeyB64.slice(14);

    await expect(
      unwrapDataKey(tampered, keyPairAlice.privateKey)
    ).rejects.toThrow();
  });

  // -------------------------------------------------------------------------
  // 3. Complete High-Level Hybrid Encryption & Decryption
  // -------------------------------------------------------------------------
  test('hybridEncryptFile and hybridDecryptFile full roundtrip with PEM public key', async () => {
    const fileContent = 'High-security financial disclosure and privacy records 2026';
    const plainBuffer = new TextEncoder().encode(fileContent).buffer;

    // Encrypt using Alice's public key PEM
    const encResult = await hybridEncryptFile(plainBuffer, keyPairAlice.publicKeyPem);

    expect(encResult.ciphertext).toBeDefined();
    expect(encResult.iv).toBeDefined();
    expect(encResult.wrapped_key).toBeDefined();
    expect(encResult.key_fingerprint).toBe(keyPairAlice.fingerprint);
    expect(encResult.algorithm).toBe('AES-GCM-256+RSA-OAEP');
    expect(encResult.version).toBe('2.0');

    // Decrypt using Alice's private CryptoKey
    const decBuffer = await hybridDecryptFile(
      base64ToArrayBuffer(encResult.ciphertext),
      encResult.wrapped_key,
      keyPairAlice.privateKey,
      encResult.iv,
      encResult.integrity_hash
    );

    const decryptedText = new TextDecoder().decode(decBuffer);
    expect(decryptedText).toBe(fileContent);
  });

  test('hybridDecryptFile rejects tampered ciphertext (GCM tag validation)', async () => {
    const plainBuffer = new TextEncoder().encode('Tamper-sensitive data').buffer;
    const encResult = await hybridEncryptFile(plainBuffer, keyPairAlice.publicKey);

    const rawCipher = new Uint8Array(base64ToArrayBuffer(encResult.ciphertext));
    // Tamper with middle byte of ciphertext
    rawCipher[Math.floor(rawCipher.length / 2)] ^= 0xff;

    await expect(
      hybridDecryptFile(
        rawCipher.buffer,
        encResult.wrapped_key,
        keyPairAlice.privateKey,
        encResult.iv,
        encResult.integrity_hash
      )
    ).rejects.toThrow(/Decryption failed/i);
  });

  test('hybridDecryptFile rejects tampered IV', async () => {
    const plainBuffer = new TextEncoder().encode('Integrity test').buffer;
    const encResult = await hybridEncryptFile(plainBuffer, keyPairAlice.publicKey);

    const ivBytes = new Uint8Array(base64ToArrayBuffer(encResult.iv));
    ivBytes[0] ^= 0x01; // flip bit in IV
    const tamperedIvB64 = arrayBufferToBase64(ivBytes.buffer);

    await expect(
      hybridDecryptFile(
        base64ToArrayBuffer(encResult.ciphertext),
        encResult.wrapped_key,
        keyPairAlice.privateKey,
        tamperedIvB64,
        encResult.integrity_hash
      )
    ).rejects.toThrow(/Decryption failed/i);
  });

  test('hybridDecryptFile rejects integrity hash mismatch after decryption', async () => {
    const plainBuffer = new TextEncoder().encode('Legitimate content').buffer;
    const encResult = await hybridEncryptFile(plainBuffer, keyPairAlice.publicKey);

    // Provide bogus expected hash
    const fakeHash = '0000000000000000000000000000000000000000000000000000000000000000';

    await expect(
      hybridDecryptFile(
        base64ToArrayBuffer(encResult.ciphertext),
        encResult.wrapped_key,
        keyPairAlice.privateKey,
        encResult.iv,
        fakeHash
      )
    ).rejects.toThrow(/Integrity verification failed/i);
  });

  // -------------------------------------------------------------------------
  // 4. End-to-End User Session Simulation (Password -> RSA -> AES -> Decrypt)
  // -------------------------------------------------------------------------
  test('Simulated user workflow: password unprotects RSA private key -> unwraps AES key -> decrypts file', async () => {
    const userPassword = 'CorrectUserSecretPassword123!';
    const userEmail = 'user@securecloud.test';

    // User creates and protects RSA keypair
    const userPair = await generateRsaKeyPair(2048);
    const protectedPriv = await protectPrivateKey(userPair.privateKey, userPassword);

    // Plaintext file uploaded with hybrid encryption
    const secretDoc = 'Classified project blueprints and architecture roadmap.';
    const plainBuffer = new TextEncoder().encode(secretDoc).buffer;
    const encResult = await hybridEncryptFile(plainBuffer, userPair.publicKeyPem);

    // On download, user provides their password
    const unprotectPriv = await unprotectPrivateKey(protectedPriv, userPassword);

    // User decrypts file
    const decrypted = await hybridDecryptFile(
      base64ToArrayBuffer(encResult.ciphertext),
      encResult.wrapped_key,
      unprotectPriv,
      encResult.iv,
      encResult.integrity_hash
    );

    expect(new TextDecoder().decode(decrypted)).toBe(secretDoc);
  });

  test('Simulated user workflow: wrong password prevents unprotecting private key', async () => {
    const userPassword = 'CorrectUserSecretPassword123!';
    const wrongPassword = 'WrongPassword456!';

    const userPair = await generateRsaKeyPair(2048);
    const protectedPriv = await protectPrivateKey(userPair.privateKey, userPassword);

    // User attempts to unprotect private key with wrong password -> fails before decrypting
    await expect(
      unprotectPrivateKey(protectedPriv, wrongPassword)
    ).rejects.toThrow(/Decryption failed/i);
  });

  // -------------------------------------------------------------------------
  // 5. Binary & Size Boundary Testing
  // -------------------------------------------------------------------------
  test('Hybrid encryption handles binary data buffers correctly', async () => {
    const binaryData = new Uint8Array(64 * 1024); // 64 KB binary buffer
    crypto.getRandomValues(binaryData);

    const encResult = await hybridEncryptFile(binaryData.buffer, keyPairAlice.publicKey);
    const decBuffer = await hybridDecryptFile(
      base64ToArrayBuffer(encResult.ciphertext),
      encResult.wrapped_key,
      keyPairAlice.privateKey,
      encResult.iv,
      encResult.integrity_hash
    );

    const decBytes = new Uint8Array(decBuffer);
    expect(decBytes.byteLength).toBe(binaryData.byteLength);
    expect(decBytes).toEqual(binaryData);
  });
});
