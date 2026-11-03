// =============================================================================
// services/rsa.test.js — Frontend RSA-OAEP Cryptography & Key Management Tests
// =============================================================================
const { TextEncoder: UtilTextEncoder, TextDecoder: UtilTextDecoder } = require('util');
const { webcrypto } = require('crypto');

global.TextEncoder = UtilTextEncoder;
global.TextDecoder = UtilTextDecoder;
if (!global.crypto || !global.crypto.subtle) {
  global.crypto = webcrypto;
}

import {
  generateRsaKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  spkiToPem,
  pemToSpki,
  calculatePublicKeyFingerprint,
  verifyPublicKeyFingerprint,
  protectPrivateKey,
  unprotectPrivateKey,
  verifyKeypairMatch,
  createKeyBackup,
  restoreKeyBackup,
  RSA_ALGORITHM,
  RSA_DEFAULT_MODULUS,
} from './rsa';

describe('Client-Side RSA-OAEP Public-Key Cryptography (Phase 6)', () => {
  const encoder = new global.TextEncoder();
  const decoder = new global.TextDecoder();

  test('generateRsaKeyPair generates 2048-bit RSA-OAEP keypair with valid PEM and fingerprint', async () => {
    const keyPair = await generateRsaKeyPair(2048);

    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
    expect(keyPair.algorithm).toBe(RSA_ALGORITHM);
    expect(keyPair.modulusLength).toBe(RSA_DEFAULT_MODULUS);
    expect(keyPair.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(keyPair.publicKeyPem).toContain('-----END PUBLIC KEY-----');
    expect(keyPair.fingerprint).toMatch(/^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  });

  test('generateRsaKeyPair enforces minimum 2048-bit modulus length', async () => {
    await expect(generateRsaKeyPair(1024)).rejects.toThrow(
      'RSA modulus length must be at least 2048 bits'
    );
  });

  test('SPKI to PEM and PEM to SPKI conversion roundtrips accurately', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const { spkiBuffer, pem } = await exportPublicKey(keyPair.publicKey);

    const reimportedSpki = pemToSpki(pem);
    const origBytes = new Uint8Array(spkiBuffer);
    const reimportedBytes = new Uint8Array(reimportedSpki);

    expect(reimportedBytes).toEqual(origBytes);
  });

  test('calculatePublicKeyFingerprint produces deterministic SHA-256 fingerprint', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const fp1 = await calculatePublicKeyFingerprint(keyPair.publicKeyPem);
    const fp2 = await calculatePublicKeyFingerprint(keyPair.publicKeyPem);

    expect(fp1).toBe(fp2);
    expect(fp1).toBe(keyPair.fingerprint);

    const isValid = await verifyPublicKeyFingerprint(fp1, keyPair.publicKeyPem);
    expect(isValid).toBe(true);

    const isInvalid = await verifyPublicKeyFingerprint('SHA256:00:11:22:33', keyPair.publicKeyPem);
    expect(isInvalid).toBe(false);
  });

  test('importPublicKey and importPrivateKey allow encryption/decryption roundtrip', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const { pem } = await exportPublicKey(keyPair.publicKey);
    const pkcs8 = await exportPrivateKey(keyPair.privateKey);

    const reimportedPublic = await importPublicKey(pem);
    const reimportedPrivate = await importPrivateKey(pkcs8);

    const message = 'Confidential key-wrapping payload for Phase 6 test';
    const plaintext = encoder.encode(message);

    const encrypted = await global.crypto.subtle.encrypt(
      { name: RSA_ALGORITHM },
      reimportedPublic,
      plaintext
    );

    const decrypted = await global.crypto.subtle.decrypt(
      { name: RSA_ALGORITHM },
      reimportedPrivate,
      encrypted
    );

    expect(decoder.decode(decrypted)).toBe(message);
  });

  test('verifyKeypairMatch validates matching keypairs and detects mismatched pairs', async () => {
    const pairA = await generateRsaKeyPair(2048);
    const pairB = await generateRsaKeyPair(2048);

    const isMatchA = await verifyKeypairMatch(pairA.publicKey, pairA.privateKey);
    expect(isMatchA).toBe(true);

    // Mismatched public and private key
    const isMismatch = await verifyKeypairMatch(pairA.publicKey, pairB.privateKey);
    expect(isMismatch).toBe(false);
  });

  test('protectPrivateKey encrypts private key with AES-256-GCM + PBKDF2 without exposing plaintext', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const password = 'KeyProtectionPass123!';

    const protectedBlob = await protectPrivateKey(keyPair.privateKey, password);

    expect(protectedBlob.encrypted_private_key).toBeDefined();
    expect(protectedBlob.iv).toBeDefined();
    expect(protectedBlob.salt).toBeDefined();
    expect(protectedBlob.algorithm).toBe('AES-GCM-256');
    expect(protectedBlob.kdf).toBe('PBKDF2-SHA256');
    expect(protectedBlob.iterations).toBe(100000);

    // Unprotect with correct password
    const restoredPrivate = await unprotectPrivateKey(protectedBlob, password);
    const match = await verifyKeypairMatch(keyPair.publicKey, restoredPrivate);
    expect(match).toBe(true);
  });

  test('unprotectPrivateKey rejects wrong password via AES-GCM tag verification', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const protectedBlob = await protectPrivateKey(keyPair.privateKey, 'CorrectPass123!');

    await expect(
      unprotectPrivateKey(protectedBlob, 'WrongPass456!')
    ).rejects.toThrow('Decryption failed: incorrect password or corrupted ciphertext');
  });

  test('unprotectPrivateKey rejects tampered encrypted private key', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const protectedBlob = await protectPrivateKey(keyPair.privateKey, 'CorrectPass123!');

    // Tamper with encrypted blob
    const tampered = {
      ...protectedBlob,
      encrypted_private_key: protectedBlob.encrypted_private_key.slice(0, -4) + 'AAAA',
    };

    await expect(
      unprotectPrivateKey(tampered, 'CorrectPass123!')
    ).rejects.toThrow();
  });

  test('createKeyBackup and restoreKeyBackup roundtrip securely with integrity checks', async () => {
    const keyPair = await generateRsaKeyPair(2048);
    const password = 'BackupPassword1!';
    const userEmail = 'alice@securecloud.test';

    const protectedPrivateKey = await protectPrivateKey(keyPair.privateKey, password);
    const backupJson = createKeyBackup(
      {
        publicKeyPem: keyPair.publicKeyPem,
        protectedPrivateKey,
        fingerprint: keyPair.fingerprint,
      },
      userEmail
    );

    expect(typeof backupJson).toBe('string');
    expect(backupJson).toContain('SECURE_CLOUD_RSA_KEY_BACKUP');
    expect(backupJson).toContain(userEmail);

    // Restore from backup
    const restored = await restoreKeyBackup(backupJson, password);
    expect(restored.userEmail).toBe(userEmail);
    expect(restored.fingerprint).toBe(keyPair.fingerprint);

    const match = await verifyKeypairMatch(restored.publicKey, restored.privateKey);
    expect(match).toBe(true);
  });

  test('restoreKeyBackup rejects backup if public key has been substituted', async () => {
    const pairA = await generateRsaKeyPair(2048);
    const pairB = await generateRsaKeyPair(2048);
    const password = 'BackupPassword1!';

    const protectedA = await protectPrivateKey(pairA.privateKey, password);
    const backupJson = createKeyBackup(
      {
        publicKeyPem: pairA.publicKeyPem,
        protectedPrivateKey: protectedA,
        fingerprint: pairA.fingerprint,
      },
      'attacker@test.com'
    );

    const parsed = JSON.parse(backupJson);
    // Attacker substitutes public key B while retaining fingerprint A
    parsed.public_key = pairB.publicKeyPem;

    await expect(
      restoreKeyBackup(JSON.stringify(parsed), password)
    ).rejects.toThrow();
  });
});
