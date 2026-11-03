// =============================================================================
// pages/PrivacyPage.js — Client-Side PII Detection, Redaction & Privacy Shield
// ZERO-KNOWLEDGE: All extraction, detection, and masking execute in the browser.
// =============================================================================
import { useState, useId, useRef, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileText,
  AlertTriangle,
  Upload,
  Download,
  Eye,
  EyeOff,
  Check,
  Copy,
  Lock,
  RefreshCw,
  Search,
  Filter,
  CreditCard,
  Hash,
  Mail,
  Phone,
  FileCheck,
  Layers,
  ArrowRight,
  Info,
  CheckCircle2,
  XCircle,
  Loader2,
  LockKeyhole,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  extractTextFromFile,
  scanPii,
  maskPii,
  rescanAndVerify,
  createMaskedFile,
} from '../services/pii';
import { encryptFile } from '../services/crypto';
import { uploadEncryptedFile } from '../services/api';

const PII_TYPE_ICONS = {
  CARD: CreditCard,
  AADHAAR: Hash,
  PAN: FileCheck,
  EMAIL: Mail,
  PHONE: Phone,
};

const PII_TYPE_COLORS = {
  CARD: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  AADHAAR: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  PAN: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  EMAIL: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  PHONE: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30',
};

export default function PrivacyPage({ token, onRefreshFiles, setActivePage, onSessionExpired }) {
  const fileInputId = useId();
  const fileInputRef = useRef(null);

  // File & Input State
  const [sourceMode, setSourceMode] = useState('file'); // 'file' | 'text'
  const [currentFile, setCurrentFile] = useState(null);
  const [rawText, setRawText] = useState('');
  const [extractedText, setExtractedText] = useState('');
  const [isExtracting, setIsExtracting] = useState(false);
  const [extractionResult, setExtractionResult] = useState(null);

  // PII Scan State
  const [scanResult, setScanResult] = useState(null);
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Masking State
  const [selectedFindingIds, setSelectedFindingIds] = useState(new Set());
  const [maskingMode, setMaskingMode] = useState('REDACT'); // 'REDACT' | 'PARTIAL'
  const [previewTab, setPreviewTab] = useState('masked'); // 'masked' | 'original'

  // Upload Masked State
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadPassword, setUploadPassword] = useState('');
  const [uploadPwVisible, setUploadPwVisible] = useState(false);
  const [isUploadingMasked, setIsUploadingMasked] = useState(false);

  // ---------------------------------------------------------------------------
  // Process File Selection
  // ---------------------------------------------------------------------------
  const handleFileSelect = async (file) => {
    if (!file) return;
    setCurrentFile(file);
    setIsExtracting(true);
    setExtractionResult(null);
    setScanResult(null);
    setExtractedText('');

    try {
      const res = await extractTextFromFile(file);
      setExtractionResult(res);

      if (res.supported && res.text) {
        setExtractedText(res.text);
        runPiiScan(res.text);
        toast.success(`Extracted text from ${file.name}`);
      } else {
        toast.error(res.reason || 'File format unsupported');
      }
    } catch (err) {
      toast.error(`Extraction failed: ${err.message}`);
    } finally {
      setIsExtracting(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Run Scan & Initialize Selection
  // ---------------------------------------------------------------------------
  const runPiiScan = (textToScan) => {
    const scan = scanPii(textToScan);
    setScanResult(scan);
    // Select all findings for redaction by default
    const allIds = new Set(scan.findings.map((f) => f.id));
    setSelectedFindingIds(allIds);
  };

  const handleManualTextScan = () => {
    if (!rawText.trim()) {
      toast.error('Enter text to scan');
      return;
    }
    setExtractedText(rawText);
    setCurrentFile({ name: 'pasted_snippet.txt', size: rawText.length });
    setExtractionResult({ supported: true, format: 'txt', text: rawText });
    runPiiScan(rawText);
    toast.success('Text scanned for sensitive PII');
  };

  // ---------------------------------------------------------------------------
  // Compute Masked Output & Verification in Real-Time
  // ---------------------------------------------------------------------------
  const maskedOutput = extractedText && scanResult
    ? maskPii(extractedText, scanResult.findings, {
        selectedFindingIds,
        maskingMode,
      })
    : null;

  const verificationResult = maskedOutput && scanResult
    ? rescanAndVerify(maskedOutput.maskedText, scanResult.findings, selectedFindingIds)
    : null;

  // ---------------------------------------------------------------------------
  // Finding Selection Handlers
  // ---------------------------------------------------------------------------
  const toggleFinding = (id) => {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (!scanResult) return;
    setSelectedFindingIds(new Set(scanResult.findings.map((f) => f.id)));
  };

  const deselectAll = () => {
    setSelectedFindingIds(new Set());
  };

  // ---------------------------------------------------------------------------
  // Download Masked File
  // ---------------------------------------------------------------------------
  const handleDownloadMasked = () => {
    if (!maskedOutput?.maskedText || !currentFile) {
      toast.error('No masked output to download');
      return;
    }

    const maskedFile = createMaskedFile(currentFile, maskedOutput.maskedText);
    const blob = new Blob([maskedOutput.maskedText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = maskedFile.name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    toast.success(`Downloaded sanitized copy "${maskedFile.name}"! Original file preserved.`);
  };

  // ---------------------------------------------------------------------------
  // Encrypt & Upload Sanitized Copy into Vault
  // ---------------------------------------------------------------------------
  const handleConfirmUploadMasked = async () => {
    if (!uploadPassword) {
      toast.error('Enter an encryption password to protect the masked file');
      return;
    }
    if (!token) {
      toast.error('You must be logged in to upload files to your vault');
      return;
    }
    if (!maskedOutput?.maskedText || !currentFile) return;

    setIsUploadingMasked(true);
    try {
      const maskedFile = createMaskedFile(currentFile, maskedOutput.maskedText);
      const enc = new TextEncoder();
      const plainBuffer = enc.encode(maskedOutput.maskedText).buffer;

      // Client-side AES-256-GCM encryption
      const encrypted = await encryptFile(plainBuffer, uploadPassword);

      // Upload to backend
      const res = await uploadEncryptedFile({
        token,
        filename: maskedFile.name,
        mime_type: maskedFile.type || 'text/plain',
        size: plainBuffer.byteLength,
        encrypted_content: encrypted.ciphertext,
        iv: encrypted.iv,
        salt: encrypted.salt || '',
        wrapped_key: '',
        key_fingerprint: '',
        integrity_hash: encrypted.integrity_hash || encrypted.hash || '',
        algorithm: encrypted.algorithm || 'AES-GCM-256',
        kdf: encrypted.kdf || 'PBKDF2-SHA256',
        iterations: encrypted.iterations || 100000,
        version: encrypted.version || '1.0',
      });
      if (res.ok) {
        toast.success(`Sanitized copy "${maskedFile.name}" encrypted & uploaded!`);
        setShowUploadModal(false);
        setUploadPassword('');
        onRefreshFiles?.();
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        onSessionExpired?.();
      } else {
        toast.error(res.data?.msg || 'Upload failed');
      }
    } catch (err) {
      toast.error(`Upload error: ${err.message}`);
    } finally {
      setIsUploadingMasked(false);
    }
  };

  // Filtered findings for table
  const filteredFindings = (scanResult?.findings || []).filter((f) => {
    const matchesType = typeFilter === 'ALL' || f.type === typeFilter;
    const matchesSearch =
      !searchQuery ||
      f.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.context.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2.5 rounded-xl bg-cyber-accent/15 text-cyber-accent shadow-[0_0_20px_rgba(0,245,255,0.15)]">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Privacy Protection &amp; PII Scanner</h1>
              <p className="text-xs text-cyber-muted mt-0.5">
                Client-side sensitive entity detection and selective redaction. Plaintext never leaves your browser.
              </p>
            </div>
          </div>
        </div>

        {/* Source Switcher */}
        <div className="flex items-center gap-1.5 p-1 bg-black/40 rounded-xl border border-white/[0.08] self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setSourceMode('file')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
              sourceMode === 'file'
                ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30'
                : 'text-cyber-muted hover:text-white'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Document Upload</span>
          </button>
          <button
            type="button"
            onClick={() => setSourceMode('text')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
              sourceMode === 'text'
                ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30'
                : 'text-cyber-muted hover:text-white'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Paste Text</span>
          </button>
        </div>
      </div>

      {/* Input Section */}
      {sourceMode === 'file' ? (
        <div
          onClick={() => fileInputRef.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            if (e.dataTransfer.files?.[0]) handleFileSelect(e.dataTransfer.files[0]);
          }}
          className="glass rounded-2xl p-8 border-2 border-dashed border-white/[0.1] hover:border-cyber-accent/40 transition-all text-center cursor-pointer group"
        >
          <input
            id={fileInputId}
            ref={fileInputRef}
            type="file"
            accept=".txt,.csv,.docx,.pdf"
            onChange={(e) => {
              if (e.target.files?.[0]) handleFileSelect(e.target.files[0]);
            }}
            className="hidden"
          />
          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="p-4 rounded-2xl bg-cyber-accent/10 text-cyber-accent group-hover:scale-110 transition-transform">
              <Upload className="w-8 h-8" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">
                Drop your document here or <span className="text-cyber-accent underline underline-offset-4">browse files</span>
              </p>
              <p className="text-xs text-cyber-muted mt-1">
                Supported formats: <strong>TXT</strong>, <strong>CSV</strong>, <strong>DOCX</strong>, and <strong>Text-based PDF</strong> (Max 50 MB)
              </p>
            </div>
            <div className="flex items-center gap-2 pt-2 text-[11px] text-amber-300/80 bg-amber-500/10 px-3 py-1.5 rounded-lg border border-amber-500/20">
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>OCR is out of scope. Scanned PDFs and image files are marked unsupported and not silently treated as clean.</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="glass rounded-2xl p-6 space-y-4">
          <label className="text-xs font-semibold text-white flex items-center justify-between">
            <span>Paste Plaintext or Raw Snippet</span>
            <span className="text-cyber-muted font-normal">{rawText.length} characters</span>
          </label>
          <textarea
            rows={5}
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste text containing emails, phones, Aadhaar numbers, PAN identifiers, or card numbers for scanning..."
            className="input-field font-mono text-xs p-3 w-full"
          />
          <div className="flex justify-end">
            <button
              type="button"
              onClick={handleManualTextScan}
              className="btn-primary text-xs py-2 px-5 flex items-center gap-2"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Scan Text for PII</span>
            </button>
          </div>
        </div>
      )}

      {/* Loading Extraction Indicator */}
      {isExtracting && (
        <div className="glass rounded-2xl p-8 text-center space-y-3">
          <Loader2 className="w-8 h-8 text-cyber-accent animate-spin mx-auto" />
          <p className="text-sm font-semibold text-white">Extracting document text client-side...</p>
          <p className="text-xs text-cyber-muted">Decompressing XML streams and parsing text blocks in your browser</p>
        </div>
      )}

      {/* Extraction Failure / Unsupported Warning */}
      {extractionResult && !extractionResult.supported && (
        <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 flex items-start gap-3 text-xs">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-rose-300 text-sm">
              {extractionResult.isScannedPdf ? 'Scanned PDF Unsupported' : 'Document Format Unsupported'}
            </p>
            <p className="mt-1 text-rose-200/90 leading-relaxed">
              {extractionResult.reason}
            </p>
            <p className="mt-2 text-[11px] text-cyber-muted">
              Security Notice: This engine strictly refuses to certify unextractable or scanned documents as clean.
            </p>
          </div>
        </div>
      )}

      {/* PII Scan Results & Privacy Controls */}
      {scanResult && extractionResult?.supported && (
        <div className="space-y-6">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="glass rounded-xl p-4 space-y-1">
              <span className="text-[11px] font-medium text-cyber-muted uppercase tracking-wider block">Total Items</span>
              <p className="text-2xl font-bold text-white">{scanResult.totalCount}</p>
              <span className="text-[10px] text-cyber-muted">{scanResult.linesCount} lines scanned</span>
            </div>

            <div className="glass rounded-xl p-4 space-y-1 border-rose-500/20">
              <span className="text-[11px] font-medium text-rose-400 uppercase tracking-wider block">Cards (Luhn)</span>
              <p className="text-2xl font-bold text-white">{scanResult.countsByType.CARD}</p>
              <span className="text-[10px] text-rose-300/70">Mod-10 Verified</span>
            </div>

            <div className="glass rounded-xl p-4 space-y-1 border-amber-500/20">
              <span className="text-[11px] font-medium text-amber-400 uppercase tracking-wider block">Aadhaar</span>
              <p className="text-2xl font-bold text-white">{scanResult.countsByType.AADHAAR}</p>
              <span className="text-[10px] text-amber-300/70">12-Digit UIDAI</span>
            </div>

            <div className="glass rounded-xl p-4 space-y-1 border-emerald-500/20">
              <span className="text-[11px] font-medium text-emerald-400 uppercase tracking-wider block">PAN (Tax)</span>
              <p className="text-2xl font-bold text-white">{scanResult.countsByType.PAN}</p>
              <span className="text-[10px] text-emerald-300/70">Categorized</span>
            </div>

            <div className="glass rounded-xl p-4 space-y-1 border-cyan-500/20">
              <span className="text-[11px] font-medium text-cyan-400 uppercase tracking-wider block">Emails</span>
              <p className="text-2xl font-bold text-white">{scanResult.countsByType.EMAIL}</p>
              <span className="text-[10px] text-cyan-300/70">RFC 5322</span>
            </div>

            <div className="glass rounded-xl p-4 space-y-1 border-indigo-500/20">
              <span className="text-[11px] font-medium text-indigo-400 uppercase tracking-wider block">Phones</span>
              <p className="text-2xl font-bold text-white">{scanResult.countsByType.PHONE}</p>
              <span className="text-[10px] text-indigo-300/70">E.164 / Mobile</span>
            </div>
          </div>

          {/* Legal / Heuristic Disclaimer Banner */}
          <div className="p-3 bg-cyber-border/40 rounded-xl border border-white/[0.06] flex items-center gap-3 text-xs text-cyber-muted">
            <Info className="w-4 h-4 text-cyber-accent flex-shrink-0" />
            <p>
              <strong className="text-white/90">Verification Disclaimer:</strong> {scanResult.disclaimer}
            </p>
          </div>

          {/* Controls Bar */}
          <div className="glass rounded-2xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-semibold text-white">Filter Category:</span>
                {['ALL', 'CARD', 'AADHAAR', 'PAN', 'EMAIL', 'PHONE'].map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTypeFilter(t)}
                    className={`px-2.5 py-1 text-[11px] font-mono rounded-lg border transition-colors ${
                      typeFilter === t
                        ? 'bg-cyber-accent/20 text-cyber-accent border-cyber-accent/40 font-semibold'
                        : 'border-white/[0.08] text-cyber-muted hover:text-white'
                    }`}
                  >
                    {t} {t !== 'ALL' ? `(${scanResult.countsByType[t]})` : `(${scanResult.totalCount})`}
                  </button>
                ))}
              </div>

              {/* Masking Mode Switcher */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-cyber-muted">Masking Strategy:</span>
                <select
                  value={maskingMode}
                  onChange={(e) => setMaskingMode(e.target.value)}
                  className="input-field text-xs py-1.5 px-3"
                >
                  <option value="REDACT">Full Redaction Tags [REDACTED-TYPE]</option>
                  <option value="PARTIAL">Partial Mask (****-1234 / XXXX-5678)</option>
                </select>
              </div>
            </div>

            {/* Quick Selection Buttons & Search */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-white/[0.06]">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={selectAll}
                  className="btn-ghost text-xs py-1 px-3 text-cyber-accent hover:bg-cyber-accent/10"
                >
                  Select All ({scanResult.findings.length})
                </button>
                <button
                  type="button"
                  onClick={deselectAll}
                  className="btn-ghost text-xs py-1 px-3 text-cyber-muted hover:text-white"
                >
                  Deselect All
                </button>
                <span className="text-xs text-cyber-muted">
                  · {selectedFindingIds.size} of {scanResult.findings.length} selected for redaction
                </span>
              </div>

              <div className="relative">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search detections..."
                  className="input-field text-xs py-1.5 px-3 pl-8 w-full sm:w-56"
                />
                <Search className="w-3.5 h-3.5 text-cyber-muted absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              </div>
            </div>
          </div>

          {/* Detections List */}
          <div className="glass rounded-2xl overflow-hidden">
            <div className="p-4 bg-black/30 border-b border-white/[0.08] flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyber-accent" />
                <span>Detected Sensitive Entities ({filteredFindings.length})</span>
              </h3>
            </div>

            {filteredFindings.length === 0 ? (
              <div className="py-8 text-center text-xs text-cyber-muted">
                {scanResult.findings.length === 0
                  ? 'No sensitive PII entities detected in this document.'
                  : 'No detections match the current filter.'}
              </div>
            ) : (
              <div className="divide-y divide-white/[0.04] max-h-80 overflow-y-auto scrollbar-cyber">
                {filteredFindings.map((finding) => {
                  const isChecked = selectedFindingIds.has(finding.id);
                  const Icon = PII_TYPE_ICONS[finding.type] || ShieldAlert;
                  const colorClass = PII_TYPE_COLORS[finding.type] || 'bg-white/10 text-white';

                  return (
                    <div
                      key={finding.id}
                      onClick={() => toggleFinding(finding.id)}
                      className={`p-3.5 flex items-start gap-3 cursor-pointer transition-colors ${
                        isChecked ? 'bg-cyber-accent/[0.03]' : 'hover:bg-white/[0.02]'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => {}} // Handled by parent div
                        className="mt-1 rounded bg-black/40 border-white/20 text-cyber-accent focus:ring-cyber-accent"
                      />

                      <div className="space-y-1.5 flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border flex items-center gap-1 ${colorClass}`}
                          >
                            <Icon className="w-3 h-3" />
                            {finding.type}
                          </span>
                          <span className="text-xs font-mono font-semibold text-white truncate max-w-xs">
                            {finding.value}
                          </span>
                          <span className="text-[11px] text-cyber-muted font-mono">
                            Line {finding.line} · Char {finding.startIndex}-{finding.endIndex}
                          </span>
                          {finding.isFalsePositiveRisk && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-amber-500/20 text-amber-300">
                              Possible False Positive
                            </span>
                          )}
                        </div>

                        <div className="text-xs text-cyber-muted font-mono bg-black/40 px-2.5 py-1.5 rounded-lg border border-white/[0.04]">
                          {finding.context}
                        </div>

                        <div className="flex items-center gap-2 text-[11px] text-cyber-muted">
                          <span className="text-cyber-accent">Rule:</span>
                          <span>{finding.validationDetails}</span>
                          <span>·</span>
                          <span>Masked Preview: <code className="text-white/80">{finding.maskedSample}</code></span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Live Document Preview Tabs */}
          <div className="glass rounded-2xl overflow-hidden space-y-0">
            <div className="flex items-center justify-between px-4 pt-3 border-b border-white/[0.08] bg-black/30">
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setPreviewTab('masked')}
                  className={`pb-3 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                    previewTab === 'masked'
                      ? 'border-cyber-accent text-cyber-accent'
                      : 'border-transparent text-cyber-muted hover:text-white'
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Sanitized / Masked Preview</span>
                </button>
                <button
                  type="button"
                  onClick={() => setPreviewTab('original')}
                  className={`pb-3 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                    previewTab === 'original'
                      ? 'border-cyber-accent text-cyber-accent'
                      : 'border-transparent text-cyber-muted hover:text-white'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Original Extracted Text</span>
                </button>
              </div>

              {/* Verification Verdict Badge */}
              {verificationResult && (
                <div
                  className={`px-3 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 mb-2 ${
                    verificationResult.status === 'CLEAN'
                      ? 'bg-cyber-green/15 text-cyber-green border border-cyber-green/30'
                      : verificationResult.status === 'PARTIALLY_MASKED'
                      ? 'bg-cyber-accent/15 text-cyber-accent border border-cyber-accent/30'
                      : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                  }`}
                >
                  {verificationResult.status === 'CLEAN' ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : verificationResult.status === 'PARTIALLY_MASKED' ? (
                    <Info className="w-3.5 h-3.5" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5" />
                  )}
                  <span>{verificationResult.message}</span>
                </div>
              )}
            </div>

            {/* Preview Box */}
            <div className="p-4 bg-black/50">
              <pre className="font-mono text-xs text-white/90 whitespace-pre-wrap max-h-72 overflow-y-auto scrollbar-cyber p-3 bg-black/40 rounded-xl border border-white/[0.04] leading-relaxed">
                {previewTab === 'masked' ? maskedOutput?.maskedText : extractedText}
              </pre>
            </div>

            {/* Action Bar */}
            <div className="p-4 bg-black/30 border-t border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs text-cyber-green">
                <Check className="w-4 h-4 flex-shrink-0" />
                <span>Original file is untouched on disk and cloud storage. A separate sanitized file will be produced.</span>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleDownloadMasked}
                  className="btn-ghost text-xs py-2 px-4 flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Sanitized File</span>
                </button>

                {token && (
                  <button
                    type="button"
                    onClick={() => setShowUploadModal(true)}
                    className="btn-primary text-xs py-2 px-4 flex items-center gap-2 shadow-[0_0_20px_rgba(0,245,255,0.2)]"
                  >
                    <Lock className="w-4 h-4" />
                    <span>Encrypt &amp; Upload Sanitized Copy</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Upload Sanitized Copy Modal */}
      {showUploadModal && currentFile && (
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowUploadModal(false);
          }}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        >
          <div className="glass max-w-md w-full rounded-2xl p-6 sm:p-8 space-y-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyber-accent/15 text-cyber-accent">
                <LockKeyhole className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Encrypt Sanitized File</h3>
                <p className="text-xs text-cyber-muted">
                  Saving separate copy: {currentFile.name.replace(/\.[^/.]+$/, '')}_masked.txt
                </p>
              </div>
            </div>

            <p className="text-xs text-cyber-muted">
              Enter a password to encrypt this sanitized file using <strong>AES-256-GCM</strong>.
              Plaintext data never leaves your browser. The original file remains unchanged.
            </p>

            <div>
              <label className="text-xs text-cyber-muted block mb-1">Encryption Password</label>
              <div className="relative">
                <input
                  type={uploadPwVisible ? 'text' : 'password'}
                  value={uploadPassword}
                  onChange={(e) => setUploadPassword(e.target.value)}
                  placeholder="Enter strong encryption password"
                  className="input-field text-xs py-2 w-full pr-9"
                />
                <button
                  type="button"
                  onClick={() => setUploadPwVisible(!uploadPwVisible)}
                  className="text-cyber-muted hover:text-white absolute right-3 top-1/2 -translate-y-1/2 p-0.5"
                >
                  {uploadPwVisible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowUploadModal(false)}
                className="btn-ghost text-xs py-2 px-4"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmUploadMasked}
                disabled={isUploadingMasked || !uploadPassword}
                className="btn-primary text-xs py-2 px-5 flex items-center gap-2"
              >
                {isUploadingMasked ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    Encrypting &amp; Uploading...
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    Encrypt &amp; Upload
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
