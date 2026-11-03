// =============================================================================
// services/pii.test.js — Unit & Integration Tests for Client-Side PII Engine
// =============================================================================
import {
  isValidLuhn,
  isValidVerhoeff,
  calculateVerhoeff,
  validatePan,
  isValidEmail,
  isValidPhone,
  scanPii,
  maskPii,
  rescanAndVerify,
  extractTextFromFile,
  createMaskedFile,
  PAN_CATEGORIES,
} from './pii';

describe('Phase 10 — PII Detection, Validation & Privacy Protection Engine', () => {
  // ---------------------------------------------------------------------------
  // 1. Validation Algorithms
  // ---------------------------------------------------------------------------
  describe('Luhn Algorithm (Card Validation)', () => {
    test('validates standard Luhn credit card numbers', () => {
      // Known valid Luhn numbers
      expect(isValidLuhn('4012888888881881')).toBe(true); // Visa test
      expect(isValidLuhn('4012 8888 8888 1881')).toBe(true); // Formatted with spaces
      expect(isValidLuhn('4012-8888-8888-1881')).toBe(true); // Formatted with dashes
    });

    test('rejects numbers that fail Luhn checksum', () => {
      expect(isValidLuhn('4012888888881882')).toBe(false); // Checksum digit wrong
      expect(isValidLuhn('4532759826412898')).toBe(false);
    });

    test('rejects repeated digits, short numbers, and invalid types', () => {
      expect(isValidLuhn('0000000000000000')).toBe(false);
      expect(isValidLuhn('1111111111111111')).toBe(false);
      expect(isValidLuhn('12345')).toBe(false);
      expect(isValidLuhn('')).toBe(false);
      expect(isValidLuhn(null)).toBe(false);
    });
  });

  describe('Verhoeff Algorithm (Aadhaar UIDAI Validation)', () => {
    test('computes check digit and validates full 12-digit Aadhaar', () => {
      const base11 = '36759832451';
      const checkDigit = calculateVerhoeff(base11);
      const fullAadhaar = base11 + checkDigit;

      expect(fullAadhaar.length).toBe(12);
      expect(isValidVerhoeff(fullAadhaar)).toBe(true);
      expect(isValidVerhoeff(`${base11.slice(0, 4)} ${base11.slice(4, 8)} ${base11.slice(8)}${checkDigit}`)).toBe(
        true
      );
    });

    test('rejects Aadhaar starting with 0 or 1 per UIDAI specifications', () => {
      expect(isValidVerhoeff('012345678901')).toBe(false);
      expect(isValidVerhoeff('123456789012')).toBe(false);
    });

    test('rejects numbers with corrupted check digits or repeated digits', () => {
      expect(isValidVerhoeff('367598324519')).toBe(false); // Corrupted check digit
      expect(isValidVerhoeff('222222222222')).toBe(false);
      expect(isValidVerhoeff('999999999999')).toBe(false);
    });
  });

  describe('PAN Validation (Income Tax India)', () => {
    test('validates authentic PAN format and detects taxpayer category', () => {
      const pResult = validatePan('ABCPE1234F'); // Individual / Person (P)
      expect(pResult.valid).toBe(true);
      expect(pResult.categoryCode).toBe('P');
      expect(pResult.category).toBe(PAN_CATEGORIES.P);

      const cResult = validatePan('XYZCT5678A'); // Company (C)
      expect(cResult.valid).toBe(true);
      expect(cResult.categoryCode).toBe('C');
      expect(cResult.category).toBe(PAN_CATEGORIES.C);

      const tResult = validatePan('AABTR9999Z'); // Trust (T)
      expect(tResult.valid).toBe(true);
      expect(tResult.categoryCode).toBe('T');
    });

    test('rejects invalid 4th-character category or incorrect pattern', () => {
      expect(validatePan('ABCDE1234F').valid).toBe(false); // 'D' is not a valid category
      expect(validatePan('ABCXE1234F').valid).toBe(false); // 'X' is not valid
      expect(validatePan('ABCPE12345').valid).toBe(false); // Last character must be a letter
      expect(validatePan('123PE1234F').valid).toBe(false); // First 3 must be letters
      expect(validatePan('SHORT').valid).toBe(false);
    });
  });

  describe('Email & Phone Validation', () => {
    test('validates standard email addresses and filters false positives', () => {
      expect(isValidEmail('alice@example.com')).toBe(true);
      expect(isValidEmail('john.doe+security@sub.corp.org')).toBe(true);

      // False positives: images and file assets
      expect(isValidEmail('image@asset.png')).toBe(false);
      expect(isValidEmail('not-an-email')).toBe(false);
      expect(isValidEmail('missing@tld')).toBe(false);
    });

    test('validates phone numbers and filters dates and invalid formats', () => {
      expect(isValidPhone('+91 9876543210')).toBe(true); // Indian mobile with +91
      expect(isValidPhone('9876543210')).toBe(true); // Indian 10-digit mobile
      expect(isValidPhone('+1 (555) 234-5678')).toBe(true); // US / NANP
      expect(isValidPhone('+44 20 7946 0958')).toBe(true); // UK E.164

      // False positives: dates and repetitive digits
      expect(isValidPhone('2026-11-01')).toBe(false); // Date YYYY-MM-DD
      expect(isValidPhone('01-11-2026')).toBe(false); // Date DD-MM-YYYY
      expect(isValidPhone('0000000000')).toBe(false);
      expect(isValidPhone('12345')).toBe(false); // Too short
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Full Document PII Scanning
  // ---------------------------------------------------------------------------
  describe('Full Document PII Scanning (scanPii)', () => {
    test('detects all 5 PII types with location, context, and checksum validation', () => {
      const baseAadhaar = '36759832451';
      const aadhaarCheck = calculateVerhoeff(baseAadhaar);
      const validAadhaar = `${baseAadhaar}${aadhaarCheck}`;

      const document = `CONFIDENTIAL CLIENT DOSSIER
Name: Rajesh Sharma
Email: rajesh.sharma@example.com
Phone: +91 9876543210
Permanent Account Number: ABCPE1234F
Aadhaar Identity: ${validAadhaar}
Primary Payment Card: 4012-8888-8888-1881
Account balance: $54,200.00`;

      const result = scanPii(document);
      expect(result.totalCount).toBe(5);
      expect(result.countsByType.EMAIL).toBe(1);
      expect(result.countsByType.PHONE).toBe(1);
      expect(result.countsByType.PAN).toBe(1);
      expect(result.countsByType.AADHAAR).toBe(1);
      expect(result.countsByType.CARD).toBe(1);

      // Verify locations & line numbers
      const emailFinding = result.findings.find((f) => f.type === 'EMAIL');
      expect(emailFinding.line).toBe(3);
      expect(emailFinding.value).toBe('rajesh.sharma@example.com');
      expect(emailFinding.context).toContain('Email: rajesh.sharma@example.com');

      const cardFinding = result.findings.find((f) => f.type === 'CARD');
      expect(cardFinding.validationDetails).toContain('Luhn Checksum Passed');
      expect(cardFinding.confidence).toBe('HIGH');

      const panFinding = result.findings.find((f) => f.type === 'PAN');
      expect(panFinding.validationDetails).toContain('Individual / Person (P)');

      const aadhaarFinding = result.findings.find((f) => f.type === 'AADHAAR');
      expect(aadhaarFinding.validationDetails).toContain('Verhoeff Checksum Valid');

      // Verify presence of disclaimer
      expect(result.disclaimer).toContain('Pattern matches indicate potential sensitive data');
    });

    test('eliminates false positive card numbers that fail Luhn', () => {
      // 16-digit number with invalid Luhn
      const text = 'Transaction reference code: 4012888888881882 for order.';
      const result = scanPii(text);
      expect(result.countsByType.CARD).toBe(0);
      expect(result.totalCount).toBe(0);
    });

    test('returns empty findings for clean text without sensitive data', () => {
      const cleanText = 'This is a clean security report. All systems operational. Zero PII present.';
      const result = scanPii(cleanText);
      expect(result.totalCount).toBe(0);
      expect(result.findings.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Selective Masking & Redaction
  // ---------------------------------------------------------------------------
  describe('Selective Masking & Redaction (maskPii)', () => {
    const text = 'User john@test.com with card 4012888888881881 and phone 9876543210.';

    test('applies full redaction tags to all findings by default', () => {
      const scan = scanPii(text);
      const masked = maskPii(text, scan.findings, { maskingMode: 'REDACT' });

      expect(masked.maskedCount).toBe(3);
      expect(masked.maskedText).toContain('[REDACTED-EMAIL]');
      expect(masked.maskedText).toContain('[REDACTED-CARD]');
      expect(masked.maskedText).toContain('[REDACTED-PHONE]');
      expect(masked.maskedText).not.toContain('john@test.com');
      expect(masked.maskedText).not.toContain('4012888888881881');
    });

    test('applies partial masking preserving structural hints', () => {
      const scan = scanPii(text);
      const masked = maskPii(text, scan.findings, { maskingMode: 'PARTIAL' });

      expect(masked.maskedCount).toBe(3);
      expect(masked.maskedText).toContain('j**n@test.com');
      expect(masked.maskedText).toContain('****-****-****-1881'); // Last 4 preserved
      expect(masked.maskedText).toContain('***-***-3210');
    });

    test('supports selective redaction where user chooses specific findings', () => {
      const scan = scanPii(text);
      // Select ONLY the card finding
      const cardFinding = scan.findings.find((f) => f.type === 'CARD');
      const selected = new Set([cardFinding.id]);

      const masked = maskPii(text, scan.findings, {
        selectedFindingIds: selected,
        maskingMode: 'REDACT',
      });

      expect(masked.maskedCount).toBe(1);
      expect(masked.unmaskedCount).toBe(2);
      expect(masked.maskedText).toContain('[REDACTED-CARD]');
      // Non-selected items remain in plaintext per user choice
      expect(masked.maskedText).toContain('john@test.com');
      expect(masked.maskedText).toContain('9876543210');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Masked Output Rescan & Verification
  // ---------------------------------------------------------------------------
  describe('Post-Masking Verification (rescanAndVerify)', () => {
    test('certifies CLEAN status when all items are redacted', () => {
      const text = 'Contact support at support@corp.com or call 9876543210.';
      const scan = scanPii(text);
      const masked = maskPii(text, scan.findings, { maskingMode: 'REDACT' });

      const verification = rescanAndVerify(masked.maskedText, scan.findings);
      expect(verification.verified).toBe(true);
      expect(verification.status).toBe('CLEAN');
      expect(verification.unmaskedCount).toBe(0);
      expect(verification.message).toContain('0 sensitive PII items detected');
    });

    test('certifies PARTIALLY_MASKED when user intentionally exempts items', () => {
      const text = 'User user@domain.com has card 4012888888881881.';
      const scan = scanPii(text);
      const cardOnly = new Set([scan.findings.find((f) => f.type === 'CARD').id]);
      const masked = maskPii(text, scan.findings, { selectedFindingIds: cardOnly });

      const verification = rescanAndVerify(masked.maskedText, scan.findings, cardOnly);
      expect(verification.verified).toBe(true);
      expect(verification.status).toBe('PARTIALLY_MASKED');
      expect(verification.message).toContain('intentionally preserved');
    });

    test('detects LEAK if targeted sensitive value is still present in output', () => {
      const originalFindings = [
        { id: 'f1', type: 'CARD', value: '4012888888881881' },
      ];
      // Simulated faulty masked text where card leaked
      const leakedText = 'Card was not masked: 4012888888881881';
      const verification = rescanAndVerify(leakedText, originalFindings, new Set(['f1']));

      expect(verification.verified).toBe(false);
      expect(verification.status).toBe('LEAK_DETECTED');
      expect(verification.message).toContain('Verification Failed');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Client-Side Document Extraction & File Handling
  // ---------------------------------------------------------------------------
  describe('Document Extraction & Original File Preservation', () => {
    test('extracts plaintext from TXT files', async () => {
      const text = 'Client PAN: ABCPE1234F';
      const file = new File([text], 'client.txt', { type: 'text/plain' });

      const res = await extractTextFromFile(file);
      expect(res.supported).toBe(true);
      expect(res.format).toBe('txt');
      expect(res.text).toBe(text);
    });

    test('extracts plaintext from CSV files', async () => {
      const csv = 'id,name,email\n1,Alice,alice@test.com\n2,Bob,bob@test.com';
      const file = new File([csv], 'users.csv', { type: 'text/csv' });

      const res = await extractTextFromFile(file);
      expect(res.supported).toBe(true);
      expect(res.format).toBe('csv');
      expect(res.text).toContain('alice@test.com');
    });

    test('extracts plaintext from text-based PDF streams', async () => {
      // Synthetic PDF with text operators
      const pdfString = `%PDF-1.4
1 0 obj
<< /Length 70 >>
stream
BT
/F1 12 Tf
72 712 Td
(Aadhaar Record: 367598324511) Tj
ET
endstream
endobj
xref
trailer
<< /Root 1 0 R >>
%%EOF`;
      const file = new File([pdfString], 'document.pdf', { type: 'application/pdf' });

      const res = await extractTextFromFile(file);
      expect(res.supported).toBe(true);
      expect(res.format).toBe('pdf');
      expect(res.text).toContain('Aadhaar Record: 367598324511');
    });

    test('extracts plaintext from zlib-compressed PDF streams without header errors', async () => {
      const zlib = require('zlib');
      const textStream = Buffer.from('BT\n/F1 12 Tf\n(Customer PAN: ABCDE1234F) Tj\nET\n');
      const compressed = zlib.deflateSync(textStream);

      const header = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length ' + compressed.length + ' >>\nstream\r\n');
      const footer = Buffer.from('\r\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');
      const pdfBytes = Buffer.concat([header, compressed, footer]);

      const file = new File([pdfBytes], 'compressed.pdf', { type: 'application/pdf' });
      const res = await extractTextFromFile(file);
      expect(res.supported).toBe(true);
      expect(res.format).toBe('pdf');
      expect(res.text).toContain('Customer PAN: ABCDE1234F');
    });

    test('extracts plaintext from raw deflate PDF streams without incorrect header check', async () => {
      const zlib = require('zlib');
      const textStream = Buffer.from('BT\n/F1 12 Tf\n[(Secret Card: ) -10 (4532015112830366)] TJ\nET\n');
      const rawDeflated = zlib.deflateRawSync(textStream);

      const header = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n');
      const footer = Buffer.from('\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');
      const pdfBytes = Buffer.concat([header, rawDeflated, footer]);

      const file = new File([pdfBytes], 'raw_compressed.pdf', { type: 'application/pdf' });
      const res = await extractTextFromFile(file);
      expect(res.supported).toBe(true);
      expect(res.format).toBe('pdf');
      expect(res.text).toContain('Secret Card: 4532015112830366');
    });

    test('strictly marks scanned PDF without text as unsupported (OCR out of scope)', async () => {
      const scannedPdf = `%PDF-1.4
1 0 obj
<< /Type /XObject /Subtype /Image /Width 100 /Height 100 >>
stream
rawimagedatabytes...
endstream
endobj
trailer
<< /Root 1 0 R >>
%%EOF`;
      const file = new File([scannedPdf], 'scanned_scan.pdf', { type: 'application/pdf' });

      const res = await extractTextFromFile(file);
      expect(res.supported).toBe(false);
      expect(res.isScannedPdf).toBe(true);
      expect(res.reason).toContain('(OCR) is out of scope');
    });

    test('strictly marks images as unsupported (OCR out of scope)', async () => {
      const file = new File(['fake-png-bytes'], 'id_card.png', { type: 'image/png' });
      const res = await extractTextFromFile(file);

      expect(res.supported).toBe(false);
      expect(res.reason).toContain('require Optical Character Recognition (OCR)');
    });

    test('strictly marks binaries as unsupported', async () => {
      const file = new File(['fake-exe-bytes'], 'installer.exe', { type: 'application/x-msdownload' });
      const res = await extractTextFromFile(file);

      expect(res.supported).toBe(false);
      expect(res.reason).toContain('Binary / archive / media formats');
    });

    test('rejects files exceeding 50 MB limit', async () => {
      const fakeLargeFile = {
        name: 'massive.txt',
        size: 55 * 1024 * 1024, // 55 MB
        arrayBuffer: async () => new ArrayBuffer(0),
      };
      const res = await extractTextFromFile(fakeLargeFile);

      expect(res.supported).toBe(false);
      expect(res.reason).toContain('exceeds maximum 50 MB');
    });

    test('createMaskedFile generates separate copy without touching original file', () => {
      const originalFile = new File(['Confidential PAN: ABCPE1234F'], 'secret_data.txt', {
        type: 'text/plain',
      });

      const maskedText = 'Confidential PAN: [REDACTED-PAN]';
      const maskedFile = createMaskedFile(originalFile, maskedText);

      // Verify original is completely untouched
      expect(originalFile.name).toBe('secret_data.txt');
      expect(originalFile.size).toBe(28);

      // Verify new file has masked name and new content
      expect(maskedFile.name).toBe('secret_data_masked.txt');
      expect(maskedFile instanceof File).toBe(true);
    });
  });
});
