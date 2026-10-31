// =============================================================================
// pages/UploadPage.js — Drag & drop upload with client-side encryption
// =============================================================================
import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Upload, Lock, CheckCircle2, AlertCircle, FileUp,
  Loader2, Shield, X, Eye, EyeOff,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { readFileAsArrayBuffer, encryptFile } from '../services/crypto';
import { uploadEncryptedFile } from '../services/api';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

const STAGES = {
  idle: { label: 'Ready', color: 'text-cyber-muted' },
  reading: { label: 'Reading file...', color: 'text-cyber-accent' },
  encrypting: { label: 'Encrypting with AES-256...', color: 'text-amber-400' },
  uploading: { label: 'Uploading encrypted data...', color: 'text-cyber-green' },
  done: { label: 'Upload complete!', color: 'text-cyber-green' },
  error: { label: 'Upload failed', color: 'text-cyber-danger' },
};

export default function UploadPage({ token, onUploadComplete }) {
  const [file, setFile] = useState(null);
  const [encPassword, setEncPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [stage, setStage] = useState('idle');
  const [progress, setProgress] = useState(0);

  // Dropzone
  const onDrop = useCallback((accepted) => {
    if (accepted.length > 0) {
      setFile(accepted[0]);
      setStage('idle');
      setProgress(0);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    maxSize: 50 * 1024 * 1024, // 50 MB
    onDropRejected: () => toast.error('File too large. Max 50 MB.'),
  });

  const removeFile = () => {
    setFile(null);
    setStage('idle');
    setProgress(0);
  };

  // ---------------------------------------------------------------------------
  // Upload handler
  // ---------------------------------------------------------------------------
  const handleUpload = async () => {
    if (!file || !encPassword || stage !== 'idle') return;

    try {
      // 1. Read file
      setStage('reading');
      setProgress(10);
      const buffer = await readFileAsArrayBuffer(file);

      // 2. Encrypt
      setStage('encrypting');
      setProgress(40);
      const { ciphertext, iv, salt } = await encryptFile(buffer, encPassword);

      // 3. Upload
      setStage('uploading');
      setProgress(70);
      const res = await uploadEncryptedFile({
        token,
        filename: file.name,
        mime_type: file.type || 'application/octet-stream',
        size: file.size,
        encrypted_content: ciphertext,
        iv,
        salt,
        file_password: encPassword,
      });

      if (!res.ok) {
        setStage('error');
        if (res.status === 401) {
          toast.error('Session expired. Please login again.');
          return;
        }
        toast.error(res.data?.msg || 'Upload failed');
        return;
      }

      setProgress(100);
      setStage('done');
      toast.success(`"${file.name}" encrypted and uploaded!`);

      // Reset after delay
      setTimeout(() => {
        setFile(null);
        setEncPassword('');
        setStage('idle');
        setProgress(0);
        onUploadComplete?.();
      }, 2000);
    } catch (err) {
      setStage('error');
      toast.error('Encryption or upload failed');
      console.error(err);
    }
  };

  const isProcessing = !['idle', 'done', 'error'].includes(stage);

  return (
    <div className="page-enter max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white mb-1">Secure Upload</h1>
        <p className="text-sm text-cyber-muted">
          Files are encrypted in your browser before they leave your device.
        </p>
      </div>

      {/* Dropzone */}
      <div
        {...getRootProps()}
        className={`
          glass p-8 text-center cursor-pointer
          transition-all duration-300 border-2 border-dashed
          ${isDragActive
            ? 'border-cyber-accent bg-cyber-accent/5 shadow-[0_0_40px_rgba(0,245,255,0.1)]'
            : file
              ? 'border-cyber-green/30 bg-cyber-green/5'
              : 'border-white/10 hover:border-cyber-accent/30 hover:bg-white/[0.02]'
          }
        `}
      >
        <input {...getInputProps()} disabled={isProcessing} />

        {file ? (
          <div className="space-y-3 animate-fade-in">
            <div className="w-14 h-14 mx-auto rounded-2xl bg-cyber-green/10
                            flex items-center justify-center">
              <FileUp className="w-7 h-7 text-cyber-green" />
            </div>
            <div>
              <p className="text-base font-semibold text-white">{file.name}</p>
              <p className="text-sm text-cyber-muted mt-1">{formatBytes(file.size)}</p>
            </div>
            {!isProcessing && stage !== 'done' && (
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); removeFile(); }}
                className="inline-flex items-center gap-1 text-xs text-cyber-danger
                           hover:text-red-400 transition-colors"
              >
                <X className="w-3 h-3" /> Remove
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            <div className="w-14 h-14 mx-auto rounded-2xl bg-cyber-accent/10
                            flex items-center justify-center animate-float">
              <Upload className="w-7 h-7 text-cyber-accent" />
            </div>
            <div>
              <p className="text-base font-medium text-white">
                {isDragActive ? 'Drop file here' : 'Drag & drop a file here'}
              </p>
              <p className="text-sm text-cyber-muted mt-1">
                or <span className="text-cyber-accent">browse</span> · Max 50 MB
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Encryption password */}
      {file && (
        <div className="glass p-6 space-y-4 animate-slide-up">
          <div className="flex items-center gap-2 mb-1">
            <Lock className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-white">Encryption Password</h3>
          </div>
          <p className="text-xs text-cyber-muted -mt-2">
            This password is used to derive your AES-256 encryption key.
            <strong className="text-amber-400"> Remember it</strong> — without it, the file
            cannot be decrypted.
          </p>
          <div className="relative">
            <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type={showPassword ? 'text' : 'password'}
              value={encPassword}
              onChange={(e) => setEncPassword(e.target.value)}
              placeholder="Enter encryption password"
              disabled={isProcessing}
              className="input-field pl-11 pr-12"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded-lg
                         text-cyber-muted hover:text-cyber-accent transition-colors"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>
      )}

      {/* Progress bar */}
      {stage !== 'idle' && (
        <div className="glass p-5 space-y-3 animate-slide-up">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {stage === 'done' ? (
                <CheckCircle2 className="w-4 h-4 text-cyber-green" />
              ) : stage === 'error' ? (
                <AlertCircle className="w-4 h-4 text-cyber-danger" />
              ) : (
                <Loader2 className="w-4 h-4 text-cyber-accent animate-spin" />
              )}
              <span className={`text-sm font-medium ${STAGES[stage]?.color}`}>
                {STAGES[stage]?.label}
              </span>
            </div>
            <span className="text-xs text-cyber-muted font-mono">{progress}%</span>
          </div>
          <div className="w-full h-2 bg-black/40 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ease-out
                ${stage === 'error'
                  ? 'bg-gradient-to-r from-cyber-danger to-cyber-pink'
                  : 'bg-gradient-to-r from-cyber-accent to-cyber-green'
                }`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Upload button */}
      {file && stage === 'idle' && (
        <button
          onClick={handleUpload}
          disabled={!encPassword || encPassword.length < 4}
          className="btn-primary w-full py-4 text-base animate-slide-up"
        >
          <Shield className="w-5 h-5" />
          Encrypt & Upload
        </button>
      )}

      {/* Security info */}
      <div className="glass p-5 animate-slide-up" style={{ animationDelay: '200ms' }}>
        <h4 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyber-green" />
          How it works
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { step: '1', title: 'Derive Key', desc: 'PBKDF2 (100k iterations) creates an AES key from your password' },
            { step: '2', title: 'Encrypt', desc: 'AES-256-GCM encrypts the file in your browser' },
            { step: '3', title: 'Upload', desc: 'Only encrypted bytes are sent to the server' },
          ].map(({ step, title, desc }) => (
            <div key={step} className="flex gap-3">
              <span className="w-6 h-6 rounded-lg bg-cyber-accent/10 text-cyber-accent
                               flex items-center justify-center text-xs font-bold flex-shrink-0">
                {step}
              </span>
              <div>
                <p className="text-xs font-semibold text-white">{title}</p>
                <p className="text-[11px] text-cyber-muted leading-relaxed">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
