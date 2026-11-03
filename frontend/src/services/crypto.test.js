// =============================================================================
// services/crypto.test.js — Frontend WebCrypto AES-GCM, PBKDF2 & Integrity tests
// =============================================================================
const { TextEncoder: UtilTextEncoder, TextDecoder: UtilTextDecoder } = require('util');
const { webcrypto } = require('crypto');

global.TextEncoder = UtilTextEncoder;
global.TextDecoder = UtilTextDecoder;
if (!global.crypto || !global.crypto.subtle) {
  global.crypto = webcrypto;
}

import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  calculateSha256,
  validateEncryptionMetadata,
  encryptFile,
  decryptFile,
  IV_LENGTH,
  SALT_LENGTH,
  PBKDF2_ITERATIONS,
  KEY_LENGTH,
} from './crypto';

describe('Client-side AES-256-GCM and PBKDF2 cryptography', () => {
  const encoder = new global.TextEncoder();
  const decoder = new global.TextDecoder();

  test('arrayBufferToBase64 and base64ToArrayBuffer roundtrip accurately', () => {
    const originalBytes = new Uint8Array([0, 1, 2, 255, 128, 64, 32, 16, 8, 4, 2, 1]);
    const b64 = arrayBufferToBase64(originalBytes.buffer);
    const roundtripBuffer = base64ToArrayBuffer(b64);
    const roundtripBytes = new Uint8Array(roundtripBuffer);

    expect(roundtripBytes).toEqual(originalBytes);
  });

  test('calculateSha256 computes consistent 64-character hex digests', async () => {
    const data = encoder.encode('Integrity test message').buffer;
    const hash1 = await calculateSha256(data);
    const hash2 = await calculateSha256(data);

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash1)).toBe(true);
  });

  test('encryptFile generates valid metadata with 96-bit IV, 128-bit salt, and SHA-256 hash', async () => {
    const message = 'Confidential test payload for Phase 5 verification';
    const plainBuffer = encoder.encode(message).buffer;
    const password = 'CorrectEncryptionPassword123!';

    const result = await encryptFile(plainBuffer, password);

    expect(result.ciphertext).toBeDefined();
    expect(result.iv).toBeDefined();
    expect(result.salt).toBeDefined();
    expect(result.hash).toBeDefined();
    expect(result.algorithm).toBe('AES-GCM-256');
    expect(result.keyLength).toBe(KEY_LENGTH);
    expect(result.kdf).toBe('PBKDF2-SHA256');
    expect(result.iterations).toBe(PBKDF2_ITERATIONS);
    expect(result.version).toBe('1.0');

    // Verify IV is exactly 12 bytes (96 bits)
    const ivBytes = new Uint8Array(base64ToArrayBuffer(result.iv));
    expect(ivBytes.byteLength).toBe(IV_LENGTH);

    // Verify salt is exactly 16 bytes (128 bits)
    const saltBytes = new Uint8Array(base64ToArrayBuffer(result.salt));
    expect(saltBytes.byteLength).toBe(SALT_LENGTH);

    // Verify plaintext hash
    const expectedPlaintextHash = await calculateSha256(plainBuffer);
    expect(result.hash).toBe(expectedPlaintextHash);
  });

  test('IV and Salt freshness: subsequent encryptions never reuse IV or Salt', async () => {
    const message = 'Same payload encrypted multiple times';
    const plainBuffer = encoder.encode(message).buffer;
    const password = 'StaticPassword123!';

    const run1 = await encryptFile(plainBuffer, password);
    const run2 = await encryptFile(plainBuffer, password);

    // Even with the same password and plaintext, IV and salt must be unique
    expect(run1.iv).not.toBe(run2.iv);
    expect(run1.salt).not.toBe(run2.salt);
    expect(run1.ciphertext).not.toBe(run2.ciphertext);
  });

  test('encryptFile and decryptFile successfully roundtrip with correct password and hash', async () => {
    const message = 'Top secret document contents with special chars: !@#$%^&*()_+~`';
    const plainBuffer = encoder.encode(message).buffer;
    const password = 'VerifiedPassword2026!';

    const { ciphertext, iv, salt, hash } = await encryptFile(plainBuffer, password);
    const cipherBuffer = base64ToArrayBuffer(ciphertext);

    // Decrypt and verify post-decryption SHA-256 integrity
    const decryptedBuffer = await decryptFile(cipherBuffer, password, iv, salt, hash);
    const decryptedText = decoder.decode(decryptedBuffer);

    expect(decryptedText).toBe(message);
  });

  test('decryptFile rejects incorrect passwords via GCM tag verification', async () => {
    const message = 'Secret message';
    const plainBuffer = encoder.encode(message).buffer;
    const correctPassword = 'PasswordOne123!';
    const wrongPassword = 'WrongPassword456!';

    const { ciphertext, iv, salt, hash } = await encryptFile(plainBuffer, correctPassword);
    const cipherBuffer = base64ToArrayBuffer(ciphertext);

    await expect(
      decryptFile(cipherBuffer, wrongPassword, iv, salt, hash)
    ).rejects.toThrow('Decryption failed: incorrect password or corrupted ciphertext');
  });

  test('decryptFile rejects tampered ciphertext via GCM authentication tag', async () => {
    const message = 'Authenticated data that must not be altered';
    const plainBuffer = encoder.encode(message).buffer;
    const password = 'IntegrityPassword1!';

    const { ciphertext, iv, salt } = await encryptFile(plainBuffer, password);
    const cipherBytes = new Uint8Array(base64ToArrayBuffer(ciphertext));

    // Tamper with a byte in the ciphertext
    cipherBytes[0] ^= 0xff;

    await expect(
      decryptFile(cipherBytes.buffer, password, iv, salt)
    ).rejects.toThrow('Decryption failed: incorrect password or corrupted ciphertext');
  });

  test('decryptFile rejects tampered IV via GCM authentication tag', async () => {
    const message = 'Authenticated data with tampered IV';
    const plainBuffer = encoder.encode(message).buffer;
    const password = 'IntegrityPassword1!';

    const { ciphertext, iv, salt } = await encryptFile(plainBuffer, password);
    const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));

    // Tamper with IV
    ivBytes[0] ^= 0x01;
    const tamperedIv = arrayBufferToBase64(ivBytes.buffer);
    const cipherBuffer = base64ToArrayBuffer(ciphertext);

    await expect(
      decryptFile(cipherBuffer, password, tamperedIv, salt)
    ).rejects.toThrow('Decryption failed: incorrect password or corrupted ciphertext');
  });

  test('validateEncryptionMetadata rejects invalid IV length or invalid base64', () => {
    // 8-byte IV (invalid, must be 12 bytes)
    const shortIv = arrayBufferToBase64(new Uint8Array(8).buffer);
    const validSalt = arrayBufferToBase64(new Uint8Array(16).buffer);

    expect(() => {
      validateEncryptionMetadata({ iv: shortIv, salt: validSalt });
    }).toThrow('Invalid IV length: expected 12 bytes (96 bits), got 8');

    // 8-byte salt (invalid, must be 16 bytes)
    const validIv = arrayBufferToBase64(new Uint8Array(12).buffer);
    const shortSalt = arrayBufferToBase64(new Uint8Array(8).buffer);

    expect(() => {
      validateEncryptionMetadata({ iv: validIv, salt: shortSalt });
    }).toThrow('Invalid salt length: expected 16 bytes (128 bits), got 8');

    // Malformed base64
    expect(() => {
      validateEncryptionMetadata({ iv: 'not-valid-b64!@#$', salt: validSalt });
    }).toThrow('Invalid base64 encoding for IV');
  });

  test('decryptFile rejects when post-decryption SHA-256 integrity check fails', async () => {
    const message = 'Integrity verification failure test';
    const plainBuffer = encoder.encode(message).buffer;
    const password = 'PasswordIntegrity123!';

    const { ciphertext, iv, salt } = await encryptFile(plainBuffer, password);
    const cipherBuffer = base64ToArrayBuffer(ciphertext);
    const spoofedHash = '0000000000000000000000000000000000000000000000000000000000000000';

    await expect(
      decryptFile(cipherBuffer, password, iv, salt, spoofedHash)
    ).rejects.toThrow('Integrity verification failed: SHA-256 mismatch');
  });

  test('encryptFile and decryptFile process large 50 MB buffer accurately', async () => {
    // 50 MB buffer test
    const size = 50 * 1024 * 1024;
    const largeBuffer = new Uint8Array(size);
    // Add distinct boundaries
    largeBuffer[0] = 0xaa;
    largeBuffer[1024] = 0xbb;
    largeBuffer[size - 1] = 0xcc;

    const password = 'LargeFilePassword50MB!';
    const { ciphertext, iv, salt, hash } = await encryptFile(largeBuffer.buffer, password);

    expect(ciphertext).toBeDefined();
    expect(hash).toHaveLength(64);

    const cipherBuffer = base64ToArrayBuffer(ciphertext);
    const decryptedBuffer = await decryptFile(cipherBuffer, password, iv, salt, hash);
    const decryptedBytes = new Uint8Array(decryptedBuffer);

    expect(decryptedBytes.byteLength).toBe(size);
    expect(decryptedBytes[0]).toBe(0xaa);
    expect(decryptedBytes[1024]).toBe(0xbb);
    expect(decryptedBytes[size - 1]).toBe(0xcc);
  }, 30000); // 30s timeout for 50MB cryptographic roundtrip
});
