
// =============================================================================
// services/rsa.js — Client-Side RSA-OAEP Public-Key Cryptography (Web Crypto)
// =============================================================================
// ZERO-KNOWLEDGE:
//   - Private keys are generated and protected entirely inside the user's browser.
//   - Cleartext private keys and passwords NEVER touch the server or cloud storage.
//   - Private keys are encrypted using AES-256-GCM + PBKDF2 before export or cloud backup.
//   - Public keys are registered on the backend with SHA-256 fingerprints to prevent
//     key substitution attacks.
// =============================================================================
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  calculateSha256,
  toArrayBuffer,
  encryptFile,
  decryptFile,
  generateDataKey,
  encryptWithDataKey,
  decryptWithDataKey,
} from './crypto.js';

export const RSA_ALGORITHM = 'RSA-OAEP';
export const RSA_DEFAULT_MODULUS = 2048;
export const RSA_HASH = 'SHA-256';

// ---------------------------------------------------------------------------
// PEM & SPKI Format Helpers
// ---------------------------------------------------------------------------
/**
 * Convert SPKI ArrayBuffer to PEM format.
 * @param {ArrayBuffer} spkiBuffer
 * @returns {string} PEM formatted public key
 */
export function spkiToPem(spkiBuffer) {
  const buf = toArrayBuffer(spkiBuffer);
  if (!buf) throw new Error('Invalid SPKI buffer provided');
  const b64 = arrayBufferToBase64(buf);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Convert PEM string to SPKI ArrayBuffer.
 * @param {string} pemStr
 * @returns {ArrayBuffer}
 */
export function pemToSpki(pemStr) {
  if (typeof pemStr !== 'string') {
    throw new Error('Public key PEM must be a string');
  }
  const clean = pemStr
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/[\r\n\s]/g, '');

  if (!clean) {
    throw new Error('Empty or invalid public key PEM content');
  }
  return base64ToArrayBuffer(clean);
}

// ---------------------------------------------------------------------------
// Fingerprint Calculation
// ---------------------------------------------------------------------------
/**
 * Calculate SHA-256 fingerprint from SPKI bytes or PEM string.
 * Returns formatted fingerprint: "SHA256:xx:xx:..."
 *
 * @param {ArrayBuffer|string} spkiOrPem
 * @returns {Promise<string>}
 */
export async function calculatePublicKeyFingerprint(spkiOrPem) {
  let spkiBuffer;
  if (typeof spkiOrPem === 'string') {
    spkiBuffer = pemToSpki(spkiOrPem);
  } else {
    spkiBuffer = toArrayBuffer(spkiOrPem);
  }

  if (!spkiBuffer) {
    throw new Error('Cannot calculate fingerprint: invalid SPKI buffer or PEM');
  }

  const hashHex = await calculateSha256(spkiBuffer);
  const pairs = hashHex.match(/.{1,2}/g) || [];
  return `SHA256:${pairs.join(':').toUpperCase()}`;
}

/**
 * Verify that a fingerprint matches a given public key PEM or SPKI buffer.
 * @param {string} fingerprint
 * @param {ArrayBuffer|string} spkiOrPem
 * @returns {Promise<boolean>}
 */
export async function verifyPublicKeyFingerprint(fingerprint, spkiOrPem) {
  if (!fingerprint || typeof fingerprint !== 'string') return false;
  try {
    const expected = await calculatePublicKeyFingerprint(spkiOrPem);
    const normActual = fingerprint.trim().toUpperCase();
    const normExpected = expected.trim().toUpperCase();

    // Support both "SHA256:XX:..." format and raw 64-char hex format
    if (normActual === normExpected) return true;
    const rawActual = normActual.replace(/^SHA256:/, '').replace(/:/g, '');
    const rawExpected = normExpected.replace(/^SHA256:/, '').replace(/:/g, '');
    return rawActual === rawExpected;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public & Private Key Import / Export
// ---------------------------------------------------------------------------
/**
 * Import a public key from PEM or SPKI ArrayBuffer into Web Crypto CryptoKey.
 * @param {string|ArrayBuffer} spkiOrPem
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(spkiOrPem) {
  let spkiBuffer;
  if (typeof spkiOrPem === 'string') {
    spkiBuffer = pemToSpki(spkiOrPem);
  } else {
    spkiBuffer = toArrayBuffer(spkiOrPem);
  }

  if (!spkiBuffer) {
    throw new Error('Invalid public key data');
  }

  return crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    {
      name: RSA_ALGORITHM,
      hash: RSA_HASH,
    },
    true, // extractable
    ['encrypt', 'wrapKey']
  );
}

/**
 * Export a public CryptoKey to PEM string and SPKI buffer.
 * @param {CryptoKey} publicKey
 * @returns {Promise<{ spkiBuffer: ArrayBuffer, pem: string, fingerprint: string }>}
 */
export async function exportPublicKey(publicKey) {
  if (!publicKey || publicKey.type !== 'public') {
    throw new Error('Invalid public CryptoKey');
  }
  const spkiBuffer = await crypto.subtle.exportKey('spki', publicKey);
  const pem = spkiToPem(spkiBuffer);
  const fingerprint = await calculatePublicKeyFingerprint(spkiBuffer);
  return { spkiBuffer, pem, fingerprint };
}

/**
 * Import a private key from PKCS#8 ArrayBuffer into Web Crypto CryptoKey.
 * @param {ArrayBuffer} pkcs8Buffer
 * @returns {Promise<CryptoKey>}
 */
export async function importPrivateKey(pkcs8Buffer) {
  const buf = toArrayBuffer(pkcs8Buffer);
  if (!buf) {
    throw new Error('Invalid PKCS#8 buffer');
  }

  return crypto.subtle.importKey(
    'pkcs8',
    buf,
    {
      name: RSA_ALGORITHM,
      hash: RSA_HASH,
    },
    true, // extractable
    ['decrypt', 'unwrapKey']
  );
}

/**
 * Export a private CryptoKey to PKCS#8 ArrayBuffer.
 * @param {CryptoKey} privateKey
 * @returns {Promise<ArrayBuffer>}
 */
export async function exportPrivateKey(privateKey) {
  if (!privateKey || privateKey.type !== 'private') {
    throw new Error('Invalid private CryptoKey');
  }
  return crypto.subtle.exportKey('pkcs8', privateKey);
}

// ---------------------------------------------------------------------------
// Key Generation
// ---------------------------------------------------------------------------
/**
 * Generate a new RSA-OAEP public/private keypair.
 *
 * @param {number} modulusLength — default 2048 bits
 * @returns {Promise<{
 *   publicKey: CryptoKey,
 *   privateKey: CryptoKey,
 *   publicKeyPem: string,
 *   fingerprint: string,
 *   algorithm: string,
 *   modulusLength: number,
 *   hash: string
 * }>}
 */
export async function generateRsaKeyPair(modulusLength = RSA_DEFAULT_MODULUS) {
  if (modulusLength < 2048) {
    throw new Error('RSA modulus length must be at least 2048 bits');
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: RSA_ALGORITHM,
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: RSA_HASH,
    },
    true, // extractable
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );

  const exported = await exportPublicKey(keyPair.publicKey);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyPem: exported.pem,
    fingerprint: exported.fingerprint,
    algorithm: RSA_ALGORITHM,
    modulusLength,
    hash: RSA_HASH,
  };
}

// ---------------------------------------------------------------------------
// Client-Side Private Key Protection (AES-256-GCM + PBKDF2)
// ---------------------------------------------------------------------------
/**
 * Encrypt a private key in the browser using AES-256-GCM with a PBKDF2-derived key.
 * ZERO-KNOWLEDGE: The password and plaintext private key are never transmitted.
 *
 * @param {CryptoKey} privateKey
 * @param {string} password
 * @returns {Promise<{
 *   encrypted_private_key: string,
 *   iv: string,
 *   salt: string,
 *   integrity_hash: string,
 *   algorithm: string,
 *   kdf: string,
 *   iterations: number,
 *   version: string
 * }>}
 */
export async function protectPrivateKey(privateKey, password) {
  if (!password || typeof password !== 'string') {
    throw new Error('Encryption password must be a non-empty string');
  }

  const pkcs8Buffer = await exportPrivateKey(privateKey);
  const enc = await encryptFile(pkcs8Buffer, password);

  return {
    encrypted_private_key: enc.ciphertext,
    iv: enc.iv,
    salt: enc.salt,
    integrity_hash: enc.integrity_hash,
    algorithm: 'AES-GCM-256',
    kdf: 'PBKDF2-SHA256',
    iterations: enc.iterations,
    version: '1.0',
  };
}

/**
 * Decrypt a protected private key in the browser and re-import it as a CryptoKey.
 * Rejects incorrect passwords or tampered blobs via GCM tag & SHA-256 integrity.
 *
 * @param {{ encrypted_private_key: string, iv: string, salt: string, integrity_hash?: string }} protectedBlob
 * @param {string} password
 * @returns {Promise<CryptoKey>}
 */
export async function unprotectPrivateKey(protectedBlob, password) {
  if (!protectedBlob || typeof protectedBlob !== 'object') {
    throw new Error('Invalid protected private key payload');
  }
  const { encrypted_private_key, iv, salt, integrity_hash } = protectedBlob;
  if (!encrypted_private_key || !iv || !salt) {
    throw new Error('Missing encrypted_private_key, iv, or salt');
  }

  const cipherBuffer = base64ToArrayBuffer(encrypted_private_key);
  const pkcs8Buffer = await decryptFile(cipherBuffer, password, iv, salt, integrity_hash || null);

  return importPrivateKey(pkcs8Buffer);
}

// ---------------------------------------------------------------------------
// Keypair Matching Verification
// ---------------------------------------------------------------------------
/**
 * Verify that a public key and private key form a valid cryptographic pair.
 * Encrypts a random 32-byte challenge with the public key and decrypts it with the private key.
 *
 * @param {CryptoKey} publicKey
 * @param {CryptoKey} privateKey
 * @returns {Promise<boolean>}
 */
export async function verifyKeypairMatch(publicKey, privateKey) {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = await crypto.subtle.encrypt(
      { name: RSA_ALGORITHM },
      publicKey,
      challenge
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: RSA_ALGORITHM },
      privateKey,
      encrypted
    );

    const decBytes = new Uint8Array(decrypted);
    if (decBytes.byteLength !== challenge.byteLength) return false;
    for (let i = 0; i < challenge.byteLength; i++) {
      if (decBytes[i] !== challenge[i]) return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Secure Key Backup & Recovery
// ---------------------------------------------------------------------------
/**
 * Create a portable, encrypted key backup document for offline storage or cloud sync.
 * ZERO-KNOWLEDGE: Contains ONLY the AES-GCM encrypted private key.
 *
 * @param {{
 *   publicKeyPem: string,
 *   protectedPrivateKey: object,
 *   fingerprint: string
 * }} keyData
 * @param {string} userEmail
 * @returns {string} Serialized JSON backup
 */
export function createKeyBackup(keyData, userEmail) {
  const { publicKeyPem, protectedPrivateKey, fingerprint } = keyData;
  if (!publicKeyPem || !protectedPrivateKey) {
    throw new Error('Incomplete key data for backup');
  }

  const backupDoc = {
    version: '1.0',
    type: 'SECURE_CLOUD_RSA_KEY_BACKUP',
    user_email: (userEmail || '').trim().toLowerCase(),
    fingerprint,
    public_key: publicKeyPem,
    protected_private_key: protectedPrivateKey,
    created_at: new Date().toISOString(),
  };

  return JSON.stringify(backupDoc, null, 2);
}

/**
 * Restore an RSA keypair from an encrypted backup string.
 *
 * @param {string} backupJson
 * @param {string} password
 * @returns {Promise<{
 *   publicKey: CryptoKey,
 *   privateKey: CryptoKey,
 *   publicKeyPem: string,
 *   fingerprint: string,
 *   userEmail: string
 * }>}
 */
export async function restoreKeyBackup(backupJson, password) {
  let doc;
  try {
    doc = typeof backupJson === 'string' ? JSON.parse(backupJson) : backupJson;
  } catch {
    throw new Error('Invalid JSON format in key backup');
  }

  if (doc.type !== 'SECURE_CLOUD_RSA_KEY_BACKUP') {
    throw new Error('Unsupported key backup format or type');
  }

  const publicKey = await importPublicKey(doc.public_key);
  const privateKey = await unprotectPrivateKey(doc.protected_private_key, password);

  // Validate that the decrypted private key matches the restored public key
  const match = await verifyKeypairMatch(publicKey, privateKey);
  if (!match) {
    throw new Error('Key validation failed: restored private key does not match public key');
  }

  // Validate fingerprint
  const validFingerprint = await verifyPublicKeyFingerprint(doc.fingerprint, doc.public_key);
  if (!validFingerprint) {
    throw new Error('Fingerprint mismatch: public key in backup has been modified');
  }

  return {
    publicKey,
    privateKey,
    publicKeyPem: doc.public_key,
    fingerprint: doc.fingerprint,
    userEmail: doc.user_email,
  };
}

// ---------------------------------------------------------------------------
// AES + RSA Key Wrapping & Unwrapping (Web Crypto API)
// ---------------------------------------------------------------------------
/**
 * Wrap (encrypt) an AES CryptoKey using an RSA-OAEP public key.
 *
 * @param {CryptoKey} dataKey — AES CryptoKey to wrap
 * @param {CryptoKey|string} rsaPublicKey — RSA public key (CryptoKey or PEM string)
 * @returns {Promise<{ wrappedKeyBuffer: ArrayBuffer, wrappedKeyB64: string }>}
 */
export async function wrapDataKey(dataKey, rsaPublicKey) {
  if (!dataKey) {
    throw new Error('Missing data key to wrap');
  }
  let pubKey = rsaPublicKey;
  if (typeof pubKey === 'string' || pubKey instanceof ArrayBuffer) {
    pubKey = await importPublicKey(pubKey);
  }
  if (!pubKey || pubKey.type !== 'public') {
    throw new Error('Invalid RSA public key for wrapping');
  }

  const wrappedBuffer = await crypto.subtle.wrapKey(
    'raw',
    dataKey,
    pubKey,
    { name: RSA_ALGORITHM }
  );

  return {
    wrappedKeyBuffer: wrappedBuffer,
    wrappedKeyB64: arrayBufferToBase64(wrappedBuffer),
  };
}

/**
 * Unwrap (decrypt) an AES CryptoKey using an RSA-OAEP private key.
 *
 * @param {ArrayBuffer|string} wrappedKey — wrapped key (bytes or base64)
 * @param {CryptoKey} rsaPrivateKey — RSA private key
 * @param {object} keyAlgorithm — unwrapped key algorithm (default { name: 'AES-GCM', length: 256 })
 * @returns {Promise<CryptoKey>}
 */
export async function unwrapDataKey(
  wrappedKey,
  rsaPrivateKey,
  keyAlgorithm = { name: 'AES-GCM', length: 256 }
) {
  if (!wrappedKey) {
    throw new Error('Missing wrapped key');
  }
  let privKey = rsaPrivateKey;
  if (!privKey || privKey.type !== 'private') {
    throw new Error('Invalid RSA private key for unwrapping');
  }

  let wrappedBytes;
  if (typeof wrappedKey === 'string') {
    wrappedBytes = base64ToArrayBuffer(wrappedKey);
  } else {
    wrappedBytes = toArrayBuffer(wrappedKey);
  }

  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      wrappedBytes,
      privKey,
      { name: RSA_ALGORITHM },
      keyAlgorithm,
      true,
      ['encrypt', 'decrypt']
    );
  } catch {
    throw new Error('Key unwrapping failed: wrong private key or corrupted wrapped key');
  }
}

// ---------------------------------------------------------------------------
// High-Level Hybrid Encryption & Decryption Orchestration
// ---------------------------------------------------------------------------
/**
 * Hybrid Encrypt a file buffer:
 *   1. Generates a fresh random 256-bit AES data key.
 *   2. Encrypts file payload using AES-256-GCM with fresh 96-bit IV.
 *   3. Computes pre-encryption SHA-256 integrity hash.
 *   4. Wraps AES key using the recipient's RSA-OAEP public key.
 *   5. Obtains/verifies public key fingerprint.
 *
 * ZERO-KNOWLEDGE: Plaintext bytes and raw AES key never leave the browser.
 *
 * @param {ArrayBuffer|ArrayBufferView} plainBuffer — file content
 * @param {CryptoKey|string} rsaPublicKey — recipient's RSA public key (CryptoKey or PEM)
 * @returns {Promise<{
 *   ciphertext: string,
 *   cipherBuffer: ArrayBuffer,
 *   iv: string,
 *   wrapped_key: string,
 *   key_fingerprint: string,
 *   integrity_hash: string,
 *   algorithm: string,
 *   version: string
 * }>}
 */
export async function hybridEncryptFile(plainBuffer, rsaPublicKey) {
  const buf = toArrayBuffer(plainBuffer);
  if (!buf) {
    throw new Error('Plaintext payload must be an ArrayBuffer');
  }

  let pubKey = rsaPublicKey;
  let fingerprint = '';

  if (typeof pubKey === 'string') {
    fingerprint = await calculatePublicKeyFingerprint(pubKey);
    pubKey = await importPublicKey(pubKey);
  } else if (pubKey && pubKey.type === 'public') {
    const exported = await exportPublicKey(pubKey);
    fingerprint = exported.fingerprint;
  } else {
    throw new Error('Valid RSA public key (PEM, SPKI, or CryptoKey) is required');
  }

  // 1. Generate unique 256-bit AES data key
  const dataKey = await generateDataKey(256);

  // 2. Encrypt file using AES-256-GCM
  const encResult = await encryptWithDataKey(buf, dataKey);

  // 3. Wrap data key using RSA-OAEP public key
  const wrapResult = await wrapDataKey(dataKey, pubKey);

  return {
    ciphertext: encResult.ciphertext,
    cipherBuffer: encResult.cipherBuffer,
    iv: encResult.iv,
    wrapped_key: wrapResult.wrappedKeyB64,
    key_fingerprint: fingerprint,
    integrity_hash: encResult.integrity_hash,
    algorithm: 'AES-GCM-256+RSA-OAEP',
    version: '2.0',
  };
}

/**
 * Hybrid Decrypt a file buffer:
 *   1. Unwraps AES data key from wrapped_key using RSA-OAEP private key.
 *   2. Decrypts ciphertext using AES-256-GCM with IV.
 *   3. Verifies 128-bit authentication tag.
 *   4. Verifies post-decryption SHA-256 integrity hash.
 *
 * @param {ArrayBuffer|ArrayBufferView} cipherBuffer — encrypted file bytes
 * @param {string} wrappedKeyB64 — base64 RSA-wrapped AES key
 * @param {CryptoKey} rsaPrivateKey — recipient's RSA private key
 * @param {string} ivB64 — base64 96-bit IV
 * @param {string|null} expectedHash — optional expected SHA-256 hash of plaintext
 * @returns {Promise<ArrayBuffer>} — decrypted plaintext bytes
 */
export async function hybridDecryptFile(
  cipherBuffer,
  wrappedKeyB64,
  rsaPrivateKey,
  ivB64,
  expectedHash = null
) {
  if (!wrappedKeyB64 || typeof wrappedKeyB64 !== 'string') {
    throw new Error('Missing or invalid wrapped_key parameter');
  }
  if (!ivB64 || typeof ivB64 !== 'string') {
    throw new Error('Missing or invalid IV parameter');
  }

  // 1. Unwrap AES data key with RSA-OAEP private key
  const dataKey = await unwrapDataKey(wrappedKeyB64, rsaPrivateKey);

  // 2. Decrypt file using AES-256-GCM and verify integrity
  return decryptWithDataKey(cipherBuffer, dataKey, ivB64, expectedHash);
}
