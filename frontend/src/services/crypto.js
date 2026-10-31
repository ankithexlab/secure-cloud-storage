// =============================================================================
// services/crypto.js — Client-side AES-256-GCM encryption (Web Crypto API)
// =============================================================================
// ZERO-KNOWLEDGE: The server NEVER sees plaintext files.
//
// Upload flow:
//   1. Generate random salt + IV
//   2. Derive AES-256 key from password via PBKDF2 (100 000 iterations)
//   3. Encrypt file bytes with AES-256-GCM
//   4. Return { ciphertext, iv, salt } as base64
//
// Download flow:
//   1. Re-derive key from password + same salt via PBKDF2
//   2. Decrypt ciphertext with AES-256-GCM using the same IV
//   3. Return plaintext bytes
// =============================================================================

const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH = 256; // bits
const IV_LENGTH = 12;   // bytes — recommended for AES-GCM
const SALT_LENGTH = 16; // bytes

// ---------------------------------------------------------------------------
// Helpers — ArrayBuffer ↔ base64
// ---------------------------------------------------------------------------
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// Key derivation (PBKDF2)
// ---------------------------------------------------------------------------
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------
/**
 * Encrypt an ArrayBuffer using AES-256-GCM.
 *
 * @param {ArrayBuffer} plainBuffer  — raw file bytes
 * @param {string}      password     — user's password (never sent to server)
 * @returns {{ ciphertext: string, iv: string, salt: string }}
 *          All values are base64-encoded.
 */
export async function encryptFile(plainBuffer, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv   = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key  = await deriveKey(password, salt);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plainBuffer
  );

  return {
    ciphertext: arrayBufferToBase64(cipherBuffer),
    iv:         arrayBufferToBase64(iv),
    salt:       arrayBufferToBase64(salt),
  };
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------
/**
 * Decrypt ciphertext using AES-256-GCM.
 *
 * @param {ArrayBuffer} cipherBuffer — encrypted bytes
 * @param {string}      password     — user's password
 * @param {string}      ivB64        — base64 IV
 * @param {string}      saltB64      — base64 salt
 * @returns {ArrayBuffer} — decrypted plaintext bytes
 */
export async function decryptFile(cipherBuffer, password, ivB64, saltB64) {
  const salt = new Uint8Array(base64ToArrayBuffer(saltB64));
  const iv   = new Uint8Array(base64ToArrayBuffer(ivB64));
  const key  = await deriveKey(password, salt);

  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    cipherBuffer
  );
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
