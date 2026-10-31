// =============================================================================
// components/Toast.js — Toast notification provider
// =============================================================================
import { Toaster } from 'react-hot-toast';

export default function ToastProvider() {
  return (
    <Toaster
      position="top-right"
      toastOptions={{
        duration: 4000,
        style: {
          background: '#1a1f2e',
          color: '#e0e7ff',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '12px',
          fontSize: '0.875rem',
          fontFamily: 'Inter, system-ui, sans-serif',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          backdropFilter: 'blur(20px)',
        },
        success: {
          iconTheme: { primary: '#00ff88', secondary: '#0a0e17' },
          style: {
            borderColor: 'rgba(0,255,136,0.3)',
          },
        },
        error: {
          iconTheme: { primary: '#ff416c', secondary: '#0a0e17' },
          style: {
            borderColor: 'rgba(255,65,108,0.3)',
          },
        },
      }}
    />
  );
}
