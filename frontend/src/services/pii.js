// =============================================================================
// services/pii.js — Client-Side PII Detection, Validation & Privacy Protection
// ZERO-KNOWLEDGE: All extraction, scanning, and masking execute in the browser.
// Plaintext documents and extracted sensitive data NEVER touch the backend.
// =============================================================================

// ---------------------------------------------------------------------------
// 1. Validation Algorithms (Luhn, Verhoeff, PAN, Phone, Email)
// ---------------------------------------------------------------------------

/**
 * Luhn Algorithm (Mod 10 Checksum) for Payment Card Number Validation.
 * Validates structural checksum of credit and debit card numbers.
 * @param {string} numStr — Raw or formatted card number string
 * @returns {boolean} — true if valid Luhn checksum
 */
export function isValidLuhn(numStr) {
  if (!numStr || typeof numStr !== 'string') return false;
  const clean = numStr.replace(/\D/g, '');
  if (clean.length < 13 || clean.length > 19) return false;
  // Discard all identical digits (e.g. 0000000000000000 or 1111111111111111)
  if (/^(\d)\1+$/.test(clean)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let digit = parseInt(clean.charAt(i), 10);
    if (isNaN(digit)) return false;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

// Verhoeff Dihedral D5 Multiplication & Permutation Tables (UIDAI Aadhaar Standard)
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/**
 * Verhoeff Algorithm Check for Indian UIDAI Aadhaar Numbers.
 * Validates dihedral D5 checksum.
 * @param {string} numStr — 12-digit string
 * @returns {boolean} — true if valid Verhoeff checksum
 */
export function isValidVerhoeff(numStr) {
  if (!numStr || typeof numStr !== 'string') return false;
  const clean = numStr.replace(/\D/g, '');
  if (clean.length !== 12) return false;
  // UIDAI specification: Aadhaar never starts with 0 or 1
  if (/^[01]/.test(clean)) return false;
  // Discard all identical digits
  if (/^(\d)\1+$/.test(clean)) return false;

  let c = 0;
  const reversed = clean.split('').reverse();
  for (let i = 0; i < reversed.length; i++) {
    const digit = parseInt(reversed[i], 10);
    if (isNaN(digit)) return false;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

/**
 * Calculate Verhoeff Check Digit for an 11-digit base number.
 */
export function calculateVerhoeff(str) {
  const clean = str.replace(/\D/g, '');
  let c = 0;
  const reversed = clean.split('').reverse();
  for (let i = 0; i < reversed.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][parseInt(reversed[i], 10)]];
  }
  return VERHOEFF_INV[c];
}

// Indian Income Tax Department PAN Taxpayer Entity Categories
export const PAN_CATEGORIES = {
  C: 'Company',
  P: 'Individual / Person',
  H: 'Hindu Undivided Family (HUF)',
  F: 'Firm / Limited Liability Partnership (LLP)',
  A: 'Association of Persons (AOP)',
  T: 'Trust',
  B: 'Body of Individuals (BOI)',
  L: 'Local Authority',
  J: 'Artificial Juridical Person',
  G: 'Government Entity',
};

/**
 * Validate Indian Permanent Account Number (PAN).
 * Format: 5 uppercase letters + 4 digits + 1 uppercase letter (e.g. ABCPE1234F)
 * 4th char is the taxpayer category.
 * @param {string} pan
 * @returns {{ valid: boolean, category?: string, categoryCode?: string }}
 */
export function validatePan(pan) {
  if (!pan || typeof pan !== 'string') return { valid: false };
  const clean = pan.trim().toUpperCase();
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(clean)) {
    return { valid: false };
  }
  const categoryCode = clean[3];
  const category = PAN_CATEGORIES[categoryCode];
  if (!category) {
    return { valid: false };
  }
  return {
    valid: true,
    categoryCode,
    category,
  };
}

/**
 * Validate Email address (RFC 5322 subset).
 * Discards image assets, common code artifacts, and invalid TLDs.
 */
export function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const clean = email.trim().toLowerCase();
  if (clean.length > 254) return false;
  // RFC subset
  const emailRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
  if (!emailRegex.test(clean)) return false;

  // Filter out false positives (e.g. example.png, schema.org, git@github)
  const parts = clean.split('@');
  if (parts.length !== 2) return false;
  const domain = parts[1];
  const invalidTlds = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'css', 'js', 'json', 'xml', 'md', 'lock'];
  const tld = domain.split('.').pop();
  if (invalidTlds.includes(tld)) return false;

  return true;
}

/**
 * Validate Phone Number.
 * Supports International (E.164), Indian (+91 / 10-digit mobile starting 6-9), and US/standard.
 * Rejects dates (2026-11-01), all-identical numbers, and short numeric sequences.
 */
export function isValidPhone(phone) {
  if (!phone || typeof phone !== 'string') return false;
  const cleanDigits = phone.replace(/\D/g, '');
  if (cleanDigits.length < 10 || cleanDigits.length > 15) return false;
  // Discard all identical digits (e.g. 0000000000, 9999999999)
  if (/^(\d)\1+$/.test(cleanDigits)) return false;

  // Discard date formats (e.g. 2026-11-01 or 19991231)
  if (/^(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])$/.test(phone.trim())) {
    return false;
  }
  if (/^(?:0[1-9]|[12]\d|3[01])[-/.](?:0[1-9]|1[0-2])[-/.](?:19|20)\d{2}$/.test(phone.trim())) {
    return false;
  }

  // Indian mobile: 10 digits starting with 6, 7, 8, 9 (with optional +91 or 0 prefix)
  const isIndian = /^(?:(?:\+?91[\s.-]?)|0)?[6-9]\d{9}$/.test(phone.trim());
  // US / NANP: 10 digits with optional +1 prefix
  const isNanp = /^(?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?[2-9]\d{2}[\s.-]?\d{4}$/.test(phone.trim());
  // General International E.164
  const isIntl = /^\+?[1-9]\d{0,3}[\s.-]?(?:\(?\d{1,4}\)?[\s.-]?){1,4}\d{2,4}$/.test(phone.trim());

  return isIndian || isNanp || isIntl;
}

// ---------------------------------------------------------------------------
// 2. Client-Side Document Text Extraction (TXT, CSV, DOCX, PDF)
// ---------------------------------------------------------------------------

/**
 * Safe UTF-8 Decoder across Browser, Node, and Test (jsdom) environments.
 */
export function decodeUtf8(buffer) {
  if (typeof TextDecoder !== 'undefined') {
    try {
      return new TextDecoder('utf-8').decode(buffer);
    } catch {
      // Fall through to Buffer/string fallback
    }
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buffer).toString('utf-8');
  }
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  try {
    return decodeURIComponent(escape(str));
  } catch {
    return str;
  }
}

/**
 * Universal ArrayBuffer Reader for Browser, Blob, and Test (jsdom) environments.
 */
export async function readFileAsArrayBuffer(file) {
  if (!file) throw new Error('No file provided for reading');
  if (file instanceof ArrayBuffer) return file;
  if (ArrayBuffer.isView(file)) {
    return file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength);
  }

  if (typeof file.arrayBuffer === 'function') {
    return await file.arrayBuffer();
  }

  if (typeof FileReader !== 'undefined') {
    return await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error('FileReader failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  }

  if (typeof file.text === 'function') {
    const text = await file.text();
    const enc = new TextEncoder();
    return enc.encode(text).buffer;
  }

  throw new Error('Unsupported file stream object');
}

/**
 * Decompress stream bytes using Web Streams API with managed writer lifecycle.
 * Prevents unhandled promise rejections on malformed/corrupted streams.
 */
async function decompressDeflateStream(bytes, format = 'deflate') {
  if (!bytes || bytes.length === 0) return new Uint8Array(0);
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();

  const writePromise = (async () => {
    try {
      await writer.write(bytes);
      await writer.close();
    } catch (_) {
      // Handled by reader rejection or caller; prevents unhandled rejection
    }
  })();

  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } catch (err) {
    try {
      await writer.abort(err);
    } catch (_) {}
    throw err;
  } finally {
    await writePromise;
  }

  const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const c of chunks) {
    result.set(c, offset);
    offset += c.length;
  }
  return result;
}

/**
 * Decompress deflate-raw bytes using Web Streams API.
 */
async function decompressDeflateRaw(bytes) {
  return decompressDeflateStream(bytes, 'deflate-raw');
}

/**
 * Decompress zlib / deflate stream using Web Streams API (used in PDF FlateDecode).
 * Falls back to raw deflate if standard zlib header check fails.
 */
async function decompressDeflateZlib(bytes) {
  try {
    return await decompressDeflateStream(bytes, 'deflate');
  } catch (zlibErr) {
    // If standard zlib header check failed or stream is raw deflate, try deflate-raw
    try {
      return await decompressDeflateStream(bytes, 'deflate-raw');
    } catch (_) {
      throw zlibErr;
    }
  }
}

/**
 * Extract word/document.xml from a DOCX zip archive.
 */
async function extractDocxText(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  const dv = new DataView(arrayBuffer);

  // 1. Locate End of Central Directory (EOCD) signature 0x06054b50
  let eocdOffset = -1;
  for (let i = bytes.byteLength - 22; i >= Math.max(0, bytes.byteLength - 65557); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) {
    throw new Error('Invalid DOCX format: missing Zip End of Central Directory header');
  }

  const cdOffset = dv.getUint32(eocdOffset + 16, true);
  const totalEntries = dv.getUint16(eocdOffset + 10, true);

  let docXmlContent = null;
  let curr = cdOffset;

  for (let e = 0; e < totalEntries && curr < bytes.byteLength; e++) {
    if (dv.getUint32(curr, true) !== 0x02014b50) break;
    const method = dv.getUint16(curr + 10, true);
    const compSize = dv.getUint32(curr + 20, true);
    const fnLen = dv.getUint16(curr + 28, true);
    const extraLen = dv.getUint16(curr + 30, true);
    const commentLen = dv.getUint16(curr + 32, true);
    const localOffset = dv.getUint32(curr + 42, true);

    const fn = decodeUtf8(bytes.subarray(curr + 46, curr + 46 + fnLen));
    if (fn === 'word/document.xml') {
      // In ZIP Local File Header (0x04034b50):
      // offset 26 = filename length, offset 28 = extra field length
      let lhFnLen = fnLen;
      let lhExtraLen = 0;
      if (localOffset + 30 <= bytes.byteLength && dv.getUint32(localOffset, true) === 0x04034b50) {
        lhFnLen = dv.getUint16(localOffset + 26, true);
        lhExtraLen = dv.getUint16(localOffset + 28, true);
      } else if (localOffset + 30 <= bytes.byteLength) {
        lhExtraLen = dv.getUint16(localOffset + 28, true);
      }
      const dataOffset = localOffset + 30 + lhFnLen + lhExtraLen;
      const compData = bytes.subarray(dataOffset, dataOffset + compSize);

      if (method === 0) {
        docXmlContent = decodeUtf8(compData);
      } else if (method === 8) {
        try {
          const decompressed = await decompressDeflateRaw(compData);
          docXmlContent = decodeUtf8(decompressed);
        } catch {
          const decompressed = await decompressDeflateZlib(compData);
          docXmlContent = decodeUtf8(decompressed);
        }
      }
      break;
    }
    curr += 46 + fnLen + extraLen + commentLen;
  }

  if (!docXmlContent) {
    throw new Error('DOCX document XML (word/document.xml) could not be located in archive');
  }

  // Parse text paragraphs from XML
  // Normalize paragraph breaks
  const withLineBreaks = docXmlContent
    .replace(/<\/w:p>/gi, '\n')
    .replace(/<w:br[^>]*\/>/gi, '\n')
    .replace(/<w:cr[^>]*\/>/gi, '\n');

  // Strip all XML tags
  const plainText = withLineBreaks.replace(/<[^>]+>/g, '');
  // Unescape standard XML entities
  return plainText
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .trim();
}

/**
 * Extract text from text-based PDF streams.
 * Strictly detects scanned image PDFs and returns unsupported classification.
 */
async function extractPdfText(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  // Decode in latin1 / binary to safely preserve raw binary stream slices
  let str = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    str += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }

  if (!str.startsWith('%PDF-')) {
    throw new Error('Invalid PDF format: missing %PDF header');
  }

  const hasImageXObject = /\/Subtype\s*\/Image/.test(str);
  const textParts = [];
  const streamRegex = /stream[\r\n]+([\s\S]*?)[\r\n]+endstream/g;
  let match;
  let totalStreamsFound = 0;

  while ((match = streamRegex.exec(str)) !== null) {
    totalStreamsFound++;
    const streamStart = match.index + match[0].indexOf('stream') + 6;
    let actualStart = streamStart;
    while (
      actualStart < bytes.length &&
      (bytes[actualStart] === 13 ||
       bytes[actualStart] === 10 ||
       bytes[actualStart] === 32 ||
       bytes[actualStart] === 9)
    ) {
      actualStart++;
    }
    const endstreamIdx = str.indexOf('endstream', actualStart);
    if (endstreamIdx === -1) continue;
    let actualEnd = endstreamIdx;
    while (
      actualEnd > actualStart &&
      (bytes[actualEnd - 1] === 13 ||
       bytes[actualEnd - 1] === 10 ||
       bytes[actualEnd - 1] === 32 ||
       bytes[actualEnd - 1] === 9)
    ) {
      actualEnd--;
    }

    const rawSlice = bytes.subarray(actualStart, actualEnd);
    let decodedText = null;

    // Attempt zlib / raw deflate decompression for /FlateDecode streams
    try {
      const decompressed = await decompressDeflateZlib(rawSlice);
      let decStr = '';
      for (let i = 0; i < decompressed.length; i += CHUNK) {
        decStr += String.fromCharCode(...decompressed.subarray(i, i + CHUNK));
      }
      decodedText = decStr;
    } catch {
      // Uncompressed stream fallback
      let rawStr = '';
      for (let i = 0; i < rawSlice.length; i += CHUNK) {
        rawStr += String.fromCharCode(...rawSlice.subarray(i, i + CHUNK));
      }
      decodedText = rawStr;
    }

    if (decodedText) {
      // Search for text drawing operators between BT and ET
      const btRegex = /BT[\s\S]*?ET/g;
      let btMatch;
      while ((btMatch = btRegex.exec(decodedText)) !== null) {
        const block = btMatch[0];
        // 1. Tj operator: (literal string) Tj
        const tjRegex = /\(([\s\S]*?)\)\s*Tj/g;
        let tj;
        while ((tj = tjRegex.exec(block)) !== null) {
          textParts.push(
            tj[1].replace(/\\\)/g, ')').replace(/\\\(/g, '(').replace(/\\\\/g, '\\')
          );
        }
        // 2. TJ array operator: [(s1) -10 (s2)] TJ or [<hex> -10 (s)] TJ
        const tjArrRegex = /\[([\s\S]*?)\]\s*TJ/g;
        let tja;
        while ((tja = tjArrRegex.exec(block)) !== null) {
          const innerTj = /\(([\s\S]*?)\)|<([0-9A-Fa-f]+)>/g;
          let inTj;
          const piece = [];
          while ((inTj = innerTj.exec(tja[1])) !== null) {
            if (inTj[1] !== undefined) {
              piece.push(
                inTj[1].replace(/\\\)/g, ')').replace(/\\\(/g, '(').replace(/\\\\/g, '\\')
              );
            } else if (inTj[2] !== undefined) {
              const hex = inTj[2];
              let decodedHex = '';
              for (let k = 0; k < hex.length; k += 2) {
                const code = parseInt(hex.substr(k, 2), 16);
                if (code >= 32 && code <= 126) {
                  decodedHex += String.fromCharCode(code);
                }
              }
              if (decodedHex) piece.push(decodedHex);
            }
          }
          if (piece.length > 0) textParts.push(piece.join(''));
        }
        // 3. Hex string operator: <48656c6c6f> Tj
        const hexRegex = /<([0-9A-Fa-f]+)>\s*Tj/g;
        let hexMatch;
        while ((hexMatch = hexRegex.exec(block)) !== null) {
          const hex = hexMatch[1];
          let decodedHex = '';
          for (let k = 0; k < hex.length; k += 2) {
            decodedHex += String.fromCharCode(parseInt(hex.substr(k, 2), 16));
          }
          textParts.push(decodedHex);
        }
      }
    }
  }

  const extracted = textParts.join('\n').trim();
  if (extracted.length === 0) {
    if (hasImageXObject || totalStreamsFound > 0) {
      return {
        supported: false,
        isScannedPdf: true,
        reason:
          'Scanned PDF detected (contains images only, no extractable text streams). Optical Character Recognition (OCR) is out of scope.',
      };
    }
    return {
      supported: false,
      reason: 'PDF document does not contain any readable text streams or text objects.',
    };
  }

  return {
    supported: true,
    format: 'pdf',
    text: extracted,
  };
}

/**
 * Universal Client-Side Text Extractor for Supported PII Scope.
 * Supported: TXT, CSV, DOCX, text-based PDF.
 * Unsupported: Scanned PDFs, Images, Binary executables, Audio/Video.
 *
 * @param {File|Blob|{ name: string, arrayBuffer: () => Promise<ArrayBuffer> }} file
 * @returns {Promise<{
 *   supported: boolean,
 *   format?: string,
 *   text?: string,
 *   reason?: string,
 *   isScannedPdf?: boolean,
 *   isExtractionFailure?: boolean,
 *   filename: string,
 *   size: number
 * }>}
 */
export async function extractTextFromFile(file) {
  if (!file) {
    throw new Error('No file provided for text extraction');
  }

  const filename = file.name || 'unnamed_file.txt';
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  const size = file.size || 0;

  // Maximum 50 MB check
  if (size > 50 * 1024 * 1024) {
    return {
      supported: false,
      filename,
      size,
      reason: 'File size exceeds maximum 50 MB security limit.',
    };
  }

  // 1. Image formats check — strictly mark as unsupported (OCR out of scope)
  const imageExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'tiff', 'svg', 'ico'];
  if (imageExts.includes(ext)) {
    return {
      supported: false,
      filename,
      size,
      reason:
        'Image files require Optical Character Recognition (OCR), which is out of scope for this privacy engine. Images are not treated as clean text.',
    };
  }

  // 2. Binary / Media formats check
  const binaryExts = ['exe', 'dll', 'bin', 'iso', 'zip', 'tar', 'gz', '7z', 'rar', 'mp3', 'mp4', 'avi', 'mov', 'wav'];
  if (binaryExts.includes(ext)) {
    return {
      supported: false,
      filename,
      size,
      reason: 'Binary / archive / media formats do not contain direct extractable text for PII analysis.',
    };
  }

  // 3. Process supported text formats
  try {
    const arrayBuffer = await readFileAsArrayBuffer(file);

    if (ext === 'txt') {
      const text = decodeUtf8(arrayBuffer);
      return { supported: true, format: 'txt', text, filename, size };
    }

    if (ext === 'csv') {
      const text = decodeUtf8(arrayBuffer);
      return { supported: true, format: 'csv', text, filename, size };
    }

    if (ext === 'docx') {
      const text = await extractDocxText(arrayBuffer);
      return { supported: true, format: 'docx', text, filename, size };
    }

    if (ext === 'pdf') {
      const res = await extractPdfText(arrayBuffer);
      return {
        ...res,
        filename,
        size,
      };
    }

    // Default for unrecognized extensions
    return {
      supported: false,
      filename,
      size,
      reason: `Unsupported file extension (.${ext}). PII scanning currently supports TXT, CSV, DOCX, and text-based PDF.`,
    };
  } catch (err) {
    return {
      supported: false,
      isExtractionFailure: true,
      filename,
      size,
      reason: `Extraction failure: ${err.message || 'Corrupted or password-protected document'}. Document cannot be parsed.`,
    };
  }
}

// ---------------------------------------------------------------------------
// 3. PII Detection Engine (Client-Side Regex + Algorithmic Verification)
// ---------------------------------------------------------------------------

/**
 * Scan a text string for sensitive PII entities.
 * Detects:
 *   - Emails (RFC 5322)
 *   - Phone Numbers (International, Indian Mobile, US/NANP)
 *   - Payment Card Numbers (Visa, Mastercard, Amex, Discover, RuPay with Luhn Check)
 *   - Aadhaar Numbers (12-digit, non-0/1 leading, Verhoeff checksum)
 *   - PAN Numbers (5 letters, 4 digits, 1 letter with entity categorization)
 *
 * @param {string} text — Plaintext document content
 * @returns {{
 *   findings: Array<{
 *     id: string,
 *     type: 'EMAIL'|'PHONE'|'CARD'|'AADHAAR'|'PAN',
 *     value: string,
 *     startIndex: number,
 *     endIndex: number,
 *     line: number,
 *     context: string,
 *     confidence: 'HIGH'|'MEDIUM',
 *     validationDetails: string,
 *     isFalsePositiveRisk: boolean,
 *     maskedSample: string
 *   }>,
 *   totalCount: number,
 *   countsByType: Record<string, number>,
 *   textLength: number,
 *   linesCount: number,
 *   disclaimer: string
 * }}
 */
export function scanPii(text) {
  if (!text || typeof text !== 'string') {
    return {
      findings: [],
      totalCount: 0,
      countsByType: { EMAIL: 0, PHONE: 0, CARD: 0, AADHAAR: 0, PAN: 0 },
      textLength: 0,
      linesCount: 0,
      disclaimer: 'Pattern matches indicate potential sensitive data based on structural rules and checksums; they do not represent verified identities.',
    };
  }

  const findings = [];
  const countsByType = { EMAIL: 0, PHONE: 0, CARD: 0, AADHAAR: 0, PAN: 0 };
  const lines = text.split('\n');

  // Compute line start index offsets for fast line number mapping
  const lineOffsets = [];
  let curOffset = 0;
  for (let i = 0; i < lines.length; i++) {
    lineOffsets.push(curOffset);
    curOffset += lines[i].length + 1; // +1 for '\n'
  }

  function getLineNumber(index) {
    let low = 0;
    let high = lineOffsets.length - 1;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (lineOffsets[mid] <= index) {
        if (mid === lineOffsets.length - 1 || lineOffsets[mid + 1] > index) {
          return mid + 1;
        }
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return 1;
  }

  function getContextSnippet(startIndex, endIndex) {
    const ctxStart = Math.max(0, startIndex - 25);
    const ctxEnd = Math.min(text.length, endIndex + 25);
    const prefix = ctxStart > 0 ? '...' : '';
    const suffix = ctxEnd < text.length ? '...' : '';
    return `${prefix}${text.slice(ctxStart, ctxEnd).replace(/[\r\n]+/g, ' ')}${suffix}`;
  }

  // Set of occupied index spans to prevent double-matching overlapping spans
  const occupiedSpans = [];
  function isSpanFree(start, end) {
    return !occupiedSpans.some(([s, e]) => Math.max(s, start) < Math.min(e, end));
  }
  function claimSpan(start, end) {
    occupiedSpans.push([start, end]);
  }

  // -------------------------------------------------------------------------
  // A. Detect Emails
  // -------------------------------------------------------------------------
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  let em;
  while ((em = emailRegex.exec(text)) !== null) {
    const val = em[0];
    const startIndex = em.index;
    const endIndex = startIndex + val.length;

    if (isValidEmail(val) && isSpanFree(startIndex, endIndex)) {
      claimSpan(startIndex, endIndex);
      countsByType.EMAIL++;
      findings.push({
        id: `finding-${findings.length}`,
        type: 'EMAIL',
        value: val,
        startIndex,
        endIndex,
        line: getLineNumber(startIndex),
        context: getContextSnippet(startIndex, endIndex),
        confidence: 'HIGH',
        validationDetails: 'RFC 5322 Format Valid',
        isFalsePositiveRisk: false,
        maskedSample: maskEmail(val),
      });
    }
  }

  // -------------------------------------------------------------------------
  // B. Detect Payment Card Numbers (with Luhn Check)
  // -------------------------------------------------------------------------
  // Matches 13 to 19 digit sequences separated by spaces or dashes
  const cardRegex = /\b(?:\d[ -]*?){13,19}\b/g;
  let cd;
  while ((cd = cardRegex.exec(text)) !== null) {
    const rawVal = cd[0];
    const cleanDigits = rawVal.replace(/\D/g, '');
    const startIndex = cd.index;
    const endIndex = startIndex + rawVal.length;

    if (cleanDigits.length >= 13 && cleanDigits.length <= 19 && isSpanFree(startIndex, endIndex)) {
      const validLuhn = isValidLuhn(cleanDigits);
      if (validLuhn) {
        claimSpan(startIndex, endIndex);
        countsByType.CARD++;
        // Identify Card Network
        let network = 'Unknown Payment Card';
        if (/^4/.test(cleanDigits)) network = 'Visa Card';
        else if (/^(?:5[1-5]|2[2-7])/.test(cleanDigits)) network = 'Mastercard';
        else if (/^3[47]/.test(cleanDigits)) network = 'American Express';
        else if (/^(?:6011|65|64[4-9])/.test(cleanDigits)) network = 'Discover';
        else if (/^(?:60|65|81|82|508|353)/.test(cleanDigits)) network = 'RuPay Card';

        findings.push({
          id: `finding-${findings.length}`,
          type: 'CARD',
          value: rawVal,
          startIndex,
          endIndex,
          line: getLineNumber(startIndex),
          context: getContextSnippet(startIndex, endIndex),
          confidence: 'HIGH',
          validationDetails: `Luhn Checksum Passed (${network})`,
          isFalsePositiveRisk: false,
          maskedSample: maskCard(rawVal),
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // C. Detect PAN Numbers (India Income Tax)
  // -------------------------------------------------------------------------
  const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
  let pn;
  while ((pn = panRegex.exec(text)) !== null) {
    const val = pn[0];
    const startIndex = pn.index;
    const endIndex = startIndex + val.length;

    if (isSpanFree(startIndex, endIndex)) {
      const panRes = validatePan(val);
      if (panRes.valid) {
        claimSpan(startIndex, endIndex);
        countsByType.PAN++;
        findings.push({
          id: `finding-${findings.length}`,
          type: 'PAN',
          value: val,
          startIndex,
          endIndex,
          line: getLineNumber(startIndex),
          context: getContextSnippet(startIndex, endIndex),
          confidence: 'HIGH',
          validationDetails: `PAN Category: ${panRes.category} (${panRes.categoryCode})`,
          isFalsePositiveRisk: false,
          maskedSample: maskPan(val),
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // D. Detect Aadhaar Numbers (12-digit, non-0/1, Verhoeff algorithm)
  // -------------------------------------------------------------------------
  const aadhaarRegex = /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g;
  let ad;
  while ((ad = aadhaarRegex.exec(text)) !== null) {
    const rawVal = ad[0];
    const cleanDigits = rawVal.replace(/\D/g, '');
    const startIndex = ad.index;
    const endIndex = startIndex + rawVal.length;

    if (cleanDigits.length === 12 && isSpanFree(startIndex, endIndex)) {
      const verhoeffPassed = isValidVerhoeff(cleanDigits);
      claimSpan(startIndex, endIndex);
      countsByType.AADHAAR++;
      findings.push({
        id: `finding-${findings.length}`,
        type: 'AADHAAR',
        value: rawVal,
        startIndex,
        endIndex,
        line: getLineNumber(startIndex),
        context: getContextSnippet(startIndex, endIndex),
        confidence: verhoeffPassed ? 'HIGH' : 'MEDIUM',
        validationDetails: verhoeffPassed
          ? 'UIDAI Verhoeff Checksum Valid (12-digit format)'
          : '12-digit Aadhaar pattern match (Verhoeff check unverified or test ID)',
        isFalsePositiveRisk: !verhoeffPassed,
        maskedSample: maskAadhaar(rawVal),
      });
    }
  }

  // -------------------------------------------------------------------------
  // E. Detect Phone Numbers
  // -------------------------------------------------------------------------
  const phoneRegex = /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}\b/g;
  let ph;
  while ((ph = phoneRegex.exec(text)) !== null) {
    const rawVal = ph[0];
    const startIndex = ph.index;
    const endIndex = startIndex + rawVal.length;

    if (isValidPhone(rawVal) && isSpanFree(startIndex, endIndex)) {
      claimSpan(startIndex, endIndex);
      countsByType.PHONE++;
      findings.push({
        id: `finding-${findings.length}`,
        type: 'PHONE',
        value: rawVal,
        startIndex,
        endIndex,
        line: getLineNumber(startIndex),
        context: getContextSnippet(startIndex, endIndex),
        confidence: 'HIGH',
        validationDetails: 'Standard Telephone Format (E.164 / Mobile / Fixed)',
        isFalsePositiveRisk: false,
        maskedSample: maskPhone(rawVal),
      });
    }
  }

  // Sort findings in ascending order of appearance in text
  findings.sort((a, b) => a.startIndex - b.startIndex);

  return {
    findings,
    totalCount: findings.length,
    countsByType,
    textLength: text.length,
    linesCount: lines.length,
    disclaimer:
      'Pattern matches indicate potential sensitive data based on structural rules and checksums; they do not represent verified identities.',
  };
}

// ---------------------------------------------------------------------------
// 4. Masking & Redaction Formatters
// ---------------------------------------------------------------------------

export function maskEmail(email) {
  const parts = email.split('@');
  if (parts.length !== 2) return '[REDACTED-EMAIL]';
  const name = parts[0];
  const domain = parts[1];
  if (name.length <= 2) {
    return `${name[0]}*@${domain}`;
  }
  return `${name[0]}${'*'.repeat(name.length - 2)}${name[name.length - 1]}@${domain}`;
}

export function maskCard(card) {
  const digits = card.replace(/\D/g, '');
  const last4 = digits.slice(-4);
  return `****-****-****-${last4}`;
}

export function maskAadhaar(aadhaar) {
  const digits = aadhaar.replace(/\D/g, '');
  const last4 = digits.slice(-4);
  return `XXXX-XXXX-${last4}`;
}

export function maskPan(pan) {
  const clean = pan.trim().toUpperCase();
  if (clean.length !== 10) return '[REDACTED-PAN]';
  // Keep first 3 chars, mask 4th & 5th, keep digits, keep check letter
  return `${clean.slice(0, 3)}XX${clean.slice(5, 9)}${clean[9]}`;
}

export function maskPhone(phone) {
  const digits = phone.replace(/\D/g, '');
  const last4 = digits.slice(-4);
  return `***-***-${last4}`;
}

/**
 * Apply selective masking / redaction to a text string based on selected finding IDs.
 *
 * @param {string} text — Original plaintext
 * @param {Array<object>} findings — Array of findings from scanPii
 * @param {{
 *   selectedFindingIds?: Set<string> | Array<string>,
 *   maskingMode?: 'REDACT' | 'PARTIAL'
 * }} options
 * @returns {{
 *   maskedText: string,
 *   maskedCount: number,
 *   unmaskedCount: number,
 *   replacements: Array<{ id: string, type: string, original: string, masked: string }>
 * }}
 */
export function maskPii(text, findings, options = {}) {
  if (!text) {
    return { maskedText: '', maskedCount: 0, unmaskedCount: 0, replacements: [] };
  }
  const { selectedFindingIds = null, maskingMode = 'REDACT' } = options;

  // If selectedFindingIds is null, mask all findings by default
  const selectedSet = selectedFindingIds
    ? selectedFindingIds instanceof Set
      ? selectedFindingIds
      : new Set(selectedFindingIds)
    : new Set(findings.map((f) => f.id));

  // Sort selected findings in REVERSE order of startIndex to avoid index drift
  const sortedFindings = [...findings]
    .filter((f) => selectedSet.has(f.id))
    .sort((a, b) => b.startIndex - a.startIndex);

  let currentText = text;
  const replacements = [];

  for (const item of sortedFindings) {
    let replacement = '';
    if (maskingMode === 'PARTIAL') {
      if (item.type === 'EMAIL') replacement = maskEmail(item.value);
      else if (item.type === 'CARD') replacement = maskCard(item.value);
      else if (item.type === 'AADHAAR') replacement = maskAadhaar(item.value);
      else if (item.type === 'PAN') replacement = maskPan(item.value);
      else if (item.type === 'PHONE') replacement = maskPhone(item.value);
      else replacement = `[REDACTED-${item.type}]`;
    } else {
      // Full Redaction
      replacement = `[REDACTED-${item.type}]`;
    }

    currentText =
      currentText.substring(0, item.startIndex) +
      replacement +
      currentText.substring(item.endIndex);

    replacements.push({
      id: item.id,
      type: item.type,
      original: item.value,
      masked: replacement,
    });
  }

  const maskedCount = sortedFindings.length;
  const unmaskedCount = findings.length - maskedCount;

  return {
    maskedText: currentText,
    maskedCount,
    unmaskedCount,
    replacements,
  };
}

// ---------------------------------------------------------------------------
// 5. Masked Output Rescan & Verification
// ---------------------------------------------------------------------------

/**
 * Rescan masked text to certify that 0 targeted sensitive items remain unmasked.
 *
 * @param {string} maskedText — The output of maskPii
 * @param {Array<object>} originalFindings — Findings from original scan
 * @param {Set<string>|Array<string>} selectedFindingIds — What was chosen to be masked
 * @returns {{
 *   verified: boolean,
 *   remainingFindings: Array<object>,
 *   unmaskedCount: number,
 *   status: 'CLEAN' | 'PARTIALLY_MASKED' | 'LEAK_DETECTED',
 *   message: string
 * }}
 */
export function rescanAndVerify(maskedText, originalFindings = [], selectedFindingIds = null) {
  const selectedSet = selectedFindingIds
    ? selectedFindingIds instanceof Set
      ? selectedFindingIds
      : new Set(selectedFindingIds)
    : new Set(originalFindings.map((f) => f.id));

  // Run full PII scan on the masked text
  const rescan = scanPii(maskedText);

  // Check if any finding in rescan matches a value that was SUPPOSED to be masked
  const selectedValues = new Set(
    originalFindings.filter((f) => selectedSet.has(f.id)).map((f) => f.value.trim())
  );

  const leakedItems = rescan.findings.filter((rf) => selectedValues.has(rf.value.trim()));

  if (leakedItems.length > 0) {
    return {
      verified: false,
      remainingFindings: rescan.findings,
      unmaskedCount: rescan.findings.length,
      status: 'LEAK_DETECTED',
      message: `Verification Failed: ${leakedItems.length} targeted PII item(s) were still detected in the output.`,
    };
  }

  if (rescan.findings.length === 0) {
    return {
      verified: true,
      remainingFindings: [],
      unmaskedCount: 0,
      status: 'CLEAN',
      message: 'Verification Passed: 0 sensitive PII items detected in the sanitized output.',
    };
  }

  // Some items were intentionally left unmasked by the user
  return {
    verified: true,
    remainingFindings: rescan.findings,
    unmaskedCount: rescan.findings.length,
    status: 'PARTIALLY_MASKED',
    message: `Verification Passed: All selected items were masked. ${rescan.findings.length} item(s) intentionally preserved per your selection.`,
  };
}

// ---------------------------------------------------------------------------
// 6. Safe File Copy Generator (NEVER modifies original file)
// ---------------------------------------------------------------------------

/**
 * Create a separate masked copy of a document.
 * Guaranteed: Original file object is completely untouched.
 *
 * @param {File|{ name: string, type: string }} originalFile
 * @param {string} maskedText — Sanitized text content
 * @returns {File} — New File object named [baseName]_masked.[ext]
 */
export function createMaskedFile(originalFile, maskedText) {
  const originalName = originalFile.name || 'document.txt';
  const dotIdx = originalName.lastIndexOf('.');
  const baseName = dotIdx !== -1 ? originalName.substring(0, dotIdx) : originalName;
  const ext = dotIdx !== -1 ? originalName.substring(dotIdx + 1) : 'txt';

  const maskedFilename = `${baseName}_masked.${ext === 'pdf' || ext === 'docx' ? 'txt' : ext}`;
  const blob = new Blob([maskedText], { type: 'text/plain;charset=utf-8' });

  return new File([blob], maskedFilename, {
    type: 'text/plain;charset=utf-8',
    lastModified: Date.now(),
  });
}
