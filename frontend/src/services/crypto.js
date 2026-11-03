// =============================================================================
// services/crypto.js — Client-side AES-256-GCM encryption (Web Crypto API)
// =============================================================================
// ZERO-KNOWLEDGE: The server NEVER sees plaintext files or encryption passwords.
//
// Cryptographic Specification:
//   - Symmetric Cipher: AES-256-GCM (RFC 5116)
//   - Authentication Tag: 128 bits (16 bytes, verified by Web Crypto)
//   - Initialization Vector: Cryptographically random 96 bits (12 bytes)
//   - Key Derivation Function: PBKDF2 with SHA-256 (RFC 8018)
//   - PBKDF2 Iterations: 100 000 iterations (OWASP recommendation)
//   - Salt: Cryptographically random 128 bits (16 bytes)
//   - Integrity Verification: SHA-256 digest calculated pre-encryption and
//     verified post-decryption.
// =============================================================================

export const PBKDF2_ITERATIONS = 100_000;
export const KEY_LENGTH = 256; // bits
export const IV_LENGTH = 12;   // bytes — 96 bits for AES-GCM
export const SALT_LENGTH = 16; // bytes — 128 bits

const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

// ---------------------------------------------------------------------------
// Helpers — ArrayBuffer ↔ base64 & Buffer normalizer
// ---------------------------------------------------------------------------
export function toArrayBuffer(val) {
  if (!val) return null;
  if (val instanceof ArrayBuffer || Object.prototype.toString.call(val) === '[object ArrayBuffer]') {
    return val;
  }
  if (ArrayBuffer.isView(val)) {
    return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
  }
  return null;
}

export function arrayBufferToBase64(buffer) {
  const buf = toArrayBuffer(buffer);
  if (!buf) throw new Error('Invalid buffer provided to arrayBufferToBase64');

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buf).toString('base64');
  }
  const bytes = new Uint8Array(buf);
  const CHUNK = 0x8000;
  const parts = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join(''));
}

export function base64ToArrayBuffer(b64) {
  if (typeof b64 !== 'string') {
    throw new Error('Base64 string expected');
  }
  const clean = b64.trim();
  if (clean.length === 0 || clean.length % 4 !== 0 || !BASE64_REGEX.test(clean)) {
    throw new Error('Invalid base64 string');
  }
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(clean, 'base64');
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// Integrity — SHA-256 digest
// ---------------------------------------------------------------------------
export async function calculateSha256(buffer) {
  const buf = toArrayBuffer(buffer);
  if (!buf) {
    throw new Error('calculateSha256 requires an ArrayBuffer');
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', buf);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Metadata Validation
// ---------------------------------------------------------------------------
export function validateEncryptionMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') {
    throw new Error('Encryption metadata must be an object');
  }
  const { iv, salt } = metadata;
  if (!iv || typeof iv !== 'string') {
    throw new Error('Missing or invalid IV in encryption metadata');
  }
  if (!salt || typeof salt !== 'string') {
    throw new Error('Missing or invalid salt in encryption metadata');
  }

  let ivBytes;
  try {
    ivBytes = base64ToArrayBuffer(iv);
  } catch {
    throw new Error('Invalid base64 encoding for IV');
  }
  if (ivBytes.byteLength !== IV_LENGTH) {
    throw new Error(`Invalid IV length: expected ${IV_LENGTH} bytes (96 bits), got ${ivBytes.byteLength}`);
  }

  let saltBytes;
  try {
    saltBytes = base64ToArrayBuffer(salt);
  } catch {
    throw new Error('Invalid base64 encoding for salt');
  }
  if (saltBytes.byteLength !== SALT_LENGTH) {
    throw new Error(`Invalid salt length: expected ${SALT_LENGTH} bytes (128 bits), got ${saltBytes.byteLength}`);
  }

  return true;
}

// ---------------------------------------------------------------------------
// Key derivation (PBKDF2)
// ---------------------------------------------------------------------------
export async function deriveKey(password, salt, extractable = true) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  let saltBytes = salt;
  if (typeof salt === 'string') {
    saltBytes = base64ToArrayBuffer(salt);
  } else if (ArrayBuffer.isView(salt)) {
    saltBytes = toArrayBuffer(salt);
  }

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    extractable,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------
/**
 * Encrypt an ArrayBuffer using AES-256-GCM.
 *
 * @param {ArrayBuffer|ArrayBufferView} plainBuffer  — raw file bytes
 * @param {string}      password     — user's password (never sent to server)
 * @returns {{
 *   ciphertext: string,
 *   iv: string,
 *   salt: string,
 *   hash: string,
 *   integrity_hash: string,
 *   algorithm: string,
 *   keyLength: number,
 *   kdf: string,
 *   iterations: number,
 *   version: string
 * }}
 */
export async function encryptFile(plainBuffer, password) {
  const buf = toArrayBuffer(plainBuffer);
  if (!buf) {
    throw new Error('Plaintext payload must be an ArrayBuffer');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }

  // 1. Calculate SHA-256 integrity hash of plaintext
  const integrityHash = await calculateSha256(buf);

  // 2. Generate cryptographically secure random 96-bit IV and 128-bit salt
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv   = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // 3. PBKDF2 key derivation (SHA-256, 100,000 iterations)
  const key  = await deriveKey(password, salt);

  // 4. AES-256-GCM encryption with 128-bit authentication tag
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    buf
  );

  return {
    ciphertext:     arrayBufferToBase64(cipherBuffer),
    iv:             arrayBufferToBase64(iv),
    salt:           arrayBufferToBase64(salt),
    hash:           integrityHash,
    integrity_hash: integrityHash,
    algorithm:      'AES-GCM-256',
    keyLength:      KEY_LENGTH,
    kdf:            'PBKDF2-SHA256',
    iterations:     PBKDF2_ITERATIONS,
    version:        '1.0',
  };
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------
/**
 * Decrypt ciphertext using AES-256-GCM, verifying authentication tag and optional SHA-256 integrity.
 *
 * @param {ArrayBuffer|ArrayBufferView} cipherBuffer — encrypted bytes
 * @param {string}      password     — user's password
 * @param {string}      ivB64        — base64 IV
 * @param {string}      saltB64      — base64 salt
 * @param {string|null} expectedHash — optional expected SHA-256 hash of plaintext
 * @returns {ArrayBuffer} — decrypted plaintext bytes
 */
export async function decryptFile(cipherBuffer, password, ivB64, saltB64, expectedHash = null) {
  const buf = toArrayBuffer(cipherBuffer);
  if (!buf) {
    throw new Error('Ciphertext payload must be an ArrayBuffer');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  if (!ivB64 || typeof ivB64 !== 'string') {
    throw new Error('Missing or invalid IV parameter');
  }
  if (!saltB64 || typeof saltB64 !== 'string') {
    throw new Error('Missing or invalid salt parameter');
  }

  // Validate metadata structure and lengths
  validateEncryptionMetadata({ iv: ivB64, salt: saltB64 });

  const salt = new Uint8Array(base64ToArrayBuffer(saltB64));
  const iv   = new Uint8Array(base64ToArrayBuffer(ivB64));
  const key  = await deriveKey(password, salt);

  // AES-256-GCM decryption — verifies 128-bit authentication tag
  let decryptedBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      buf
    );
  } catch {
    throw new Error('Decryption failed: incorrect password or corrupted ciphertext');
  }

  // Post-decryption SHA-256 integrity verification
  if (expectedHash && typeof expectedHash === 'string' && expectedHash.trim().length > 0) {
    const actualHash = await calculateSha256(decryptedBuffer);
    if (actualHash.toLowerCase() !== expectedHash.trim().toLowerCase()) {
      throw new Error(
        `Integrity verification failed: SHA-256 mismatch (expected ${expectedHash}, got ${actualHash})`
      );
    }
  }

  return decryptedBuffer;
}

// ---------------------------------------------------------------------------
// Direct Data Key (AES-256-GCM) — For Hybrid Encryption
// ---------------------------------------------------------------------------
/**
 * Generate a fresh cryptographically secure random 256-bit AES data key.
 *
 * @param {number} length — key length in bits (default 256)
 * @returns {Promise<CryptoKey>}
 */
export async function generateDataKey(length = KEY_LENGTH) {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt an ArrayBuffer using a raw AES-256-GCM data key.
 *
 * @param {ArrayBuffer|ArrayBufferView} plainBuffer — raw file bytes
 * @param {CryptoKey}                   aesKey      — AES-GCM CryptoKey
 * @returns {Promise<{
 *   ciphertext: string,
 *   cipherBuffer: ArrayBuffer,
 *   iv: string,
 *   integrity_hash: string,
 *   algorithm: string,
 *   version: string
 * }>}
 */
export async function encryptWithDataKey(plainBuffer, aesKey) {
  const buf = toArrayBuffer(plainBuffer);
  if (!buf) {
    throw new Error('Plaintext payload must be an ArrayBuffer');
  }
  if (!aesKey) {
    throw new Error('Valid AES CryptoKey required');
  }

  // 1. Calculate SHA-256 integrity hash of plaintext
  const integrityHash = await calculateSha256(buf);

  // 2. Generate cryptographically random 96-bit IV (12 bytes)
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // 3. Encrypt via AES-256-GCM with 128-bit authentication tag
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    buf
  );

  return {
    ciphertext:     arrayBufferToBase64(cipherBuffer),
    cipherBuffer,
    iv:             arrayBufferToBase64(iv),
    hash:           integrityHash,
    integrity_hash: integrityHash,
    algorithm:      'AES-GCM-256',
    version:        '2.0',
  };
}

/**
 * Decrypt ciphertext using an AES-256-GCM data key.
 *
 * @param {ArrayBuffer|ArrayBufferView} cipherBuffer — encrypted bytes
 * @param {CryptoKey}                   aesKey       — AES-GCM CryptoKey
 * @param {string}                      ivB64        — base64 IV
 * @param {string|null}                 expectedHash — optional expected SHA-256 hash of plaintext
 * @returns {Promise<ArrayBuffer>} — decrypted plaintext bytes
 */
export async function decryptWithDataKey(cipherBuffer, aesKey, ivB64, expectedHash = null) {
  const buf = toArrayBuffer(cipherBuffer);
  if (!buf) {
    throw new Error('Ciphertext payload must be an ArrayBuffer');
  }
  if (!aesKey) {
    throw new Error('Valid AES CryptoKey required');
  }
  if (!ivB64 || typeof ivB64 !== 'string') {
    throw new Error('Missing or invalid IV parameter');
  }

  let ivBytes;
  try {
    ivBytes = base64ToArrayBuffer(ivB64);
  } catch {
    throw new Error('Invalid base64 encoding for IV');
  }
  if (ivBytes.byteLength !== IV_LENGTH) {
    throw new Error(`Invalid IV length: expected ${IV_LENGTH} bytes (96 bits), got ${ivBytes.byteLength}`);
  }

  // AES-256-GCM decryption — verifies 128-bit authentication tag
  let decryptedBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(ivBytes), tagLength: 128 },
      aesKey,
      buf
    );
  } catch {
    throw new Error('Decryption failed: corrupted ciphertext, invalid tag, or mismatched key');
  }

  // Post-decryption SHA-256 integrity verification
  if (expectedHash && typeof expectedHash === 'string' && expectedHash.trim().length > 0) {
    const actualHash = await calculateSha256(decryptedBuffer);
    if (actualHash.toLowerCase() !== expectedHash.trim().toLowerCase()) {
      throw new Error(
        `Integrity verification failed: SHA-256 mismatch (expected ${expectedHash}, got ${actualHash})`
      );
    }
  }

  return decryptedBuffer;
}

// ---------------------------------------------------------------------------
// File reader helper
// ---------------------------------------------------------------------------
export function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsArrayBuffer(file);
  });
}
