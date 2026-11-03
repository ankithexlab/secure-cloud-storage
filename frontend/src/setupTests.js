// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom

// Polyfill Web Streams DecompressionStream/CompressionStream for Node/Jest environment
try {
  const { DecompressionStream, CompressionStream } = require('node:stream/web');
  if (typeof global.DecompressionStream === 'undefined') {
    global.DecompressionStream = DecompressionStream;
  }
  if (typeof window !== 'undefined' && typeof window.DecompressionStream === 'undefined') {
    window.DecompressionStream = DecompressionStream;
  }
  if (typeof global.CompressionStream === 'undefined') {
    global.CompressionStream = CompressionStream;
  }
  if (typeof window !== 'undefined' && typeof window.CompressionStream === 'undefined') {
    window.CompressionStream = CompressionStream;
  }
} catch (_) {}

// Polyfill TextEncoder / TextDecoder for Node/Jest environment
try {
  const { TextEncoder, TextDecoder } = require('node:util');
  if (typeof global.TextEncoder === 'undefined') {
    global.TextEncoder = TextEncoder;
  }
  if (typeof window !== 'undefined' && typeof window.TextEncoder === 'undefined') {
    window.TextEncoder = TextEncoder;
  }
  if (typeof global.TextDecoder === 'undefined') {
    global.TextDecoder = TextDecoder;
  }
  if (typeof window !== 'undefined' && typeof window.TextDecoder === 'undefined') {
    window.TextDecoder = TextDecoder;
  }
} catch (_) {}

// Polyfill WebCrypto for Node/Jest environment
try {
  const { webcrypto } = require('node:crypto');
  if (!global.crypto || !global.crypto.subtle) {
    global.crypto = webcrypto;
  }
  if (typeof window !== 'undefined' && (!window.crypto || !window.crypto.subtle)) {
    window.crypto = webcrypto;
  }
} catch (_) {}
