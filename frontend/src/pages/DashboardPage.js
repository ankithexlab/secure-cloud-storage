// =============================================================================
// pages/DashboardPage.js — Overview with stats and recent activity
// =============================================================================
import { Files, HardDrive, Upload, ShieldCheck, TrendingUp, Clock } from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

const STAT_CARDS = [
  {
    id: 'files',
    label: 'Total Files',
    icon: Files,
    color: 'from-cyber-accent to-cyan-400',
    iconBg: 'bg-cyber-accent/10',
    iconColor: 'text-cyber-accent',
    getValue: (s) => s.total_files ?? 0,
  },
  {
    id: 'storage',
    label: 'Storage Used',
    icon: HardDrive,
    color: 'from-cyber-violet to-purple-400',
    iconBg: 'bg-cyber-violet/10',
    iconColor: 'text-cyber-violet',
    getValue: (s) => formatBytes(s.total_size ?? 0),
  },
  {
    id: 'uploads',
    label: 'Uploads',
    icon: Upload,
    color: 'from-cyber-green to-emerald-400',
    iconBg: 'bg-cyber-green/10',
    iconColor: 'text-cyber-green',
    getValue: (s) => s.total_files ?? 0,
  },
  {
    id: 'security',
    label: 'Encryption',
    icon: ShieldCheck,
    color: 'from-amber-400 to-orange-400',
    iconBg: 'bg-amber-400/10',
    iconColor: 'text-amber-400',
    getValue: () => 'AES-256',
  },
];

export default function DashboardPage({ stats, files, setActivePage }) {
  const recentFiles = (files || []).slice(0, 5);

  return (
    <div className="page-enter space-y-8">
      {/* Greeting */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white mb-1">
          Welcome back <span className="gradient-text">👋</span>
        </h1>
        <p className="text-cyber-muted text-sm">
          Your files are encrypted and secure. Here's your vault overview.
        </p>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {STAT_CARDS.map(({ id, label, icon: Icon, color, iconBg, iconColor, getValue }, idx) => (
          <div
            key={id}
            className="glass glass-hover relative overflow-hidden p-6 animate-slide-up"
            style={{ animationDelay: `${idx * 80}ms` }}
          >
            {/* Top accent */}
            <div className={`absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r ${color}`} />

            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-cyber-muted font-medium uppercase tracking-wider mb-2">
                  {label}
                </p>
                <p className="text-2xl font-bold text-white">{getValue(stats)}</p>
              </div>
              <div className={`w-11 h-11 rounded-xl ${iconBg} flex items-center justify-center`}>
                <Icon className={`w-5 h-5 ${iconColor}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Activity chart placeholder + recent files */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Security status */}
        <div className="lg:col-span-2 glass p-6 animate-slide-up" style={{ animationDelay: '300ms' }}>
          <div className="flex items-center gap-2 mb-5">
            <TrendingUp className="w-5 h-5 text-cyber-accent" />
            <h3 className="text-base font-semibold text-white">Security Status</h3>
          </div>

          <div className="space-y-4">
            {[
              { label: 'Encryption', value: 'AES-256-GCM', color: 'bg-cyber-green' },
              { label: 'Key Derivation', value: 'PBKDF2 · 100k iter', color: 'bg-cyber-accent' },
              { label: 'Architecture', value: 'Zero-Knowledge', color: 'bg-cyber-violet' },
              { label: 'Storage', value: 'S3 · Encrypted', color: 'bg-amber-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                <div className="flex items-center gap-3">
                  <span className={`w-2 h-2 rounded-full ${color}`} />
                  <span className="text-sm text-cyber-muted">{label}</span>
                </div>
                <span className="text-sm font-medium text-white font-mono">{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent files */}
        <div className="lg:col-span-3 glass p-6 animate-slide-up" style={{ animationDelay: '400ms' }}>
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-cyber-accent" />
              <h3 className="text-base font-semibold text-white">Recent Files</h3>
            </div>
            {files?.length > 0 && (
              <button
                onClick={() => setActivePage('files')}
                className="text-xs font-medium text-cyber-accent hover:text-cyber-green transition-colors"
              >
                View all →
              </button>
            )}
          </div>

          {recentFiles.length === 0 ? (
            <div className="text-center py-10">
              <Files className="w-12 h-12 text-white/10 mx-auto mb-3" />
              <p className="text-sm text-cyber-muted">No files uploaded yet</p>
              <button
                onClick={() => setActivePage('upload')}
                className="mt-3 text-xs text-cyber-accent hover:text-cyber-green transition-colors"
              >
                Upload your first file →
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {recentFiles.map((f) => (
                <div
                  key={f.id}
                  className="flex items-center justify-between p-3 rounded-xl
                             bg-white/[0.02] hover:bg-white/[0.05]
                             border border-transparent hover:border-white/[0.05]
                             transition-all duration-200"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-lg bg-cyber-accent/10
                                    flex items-center justify-center flex-shrink-0">
                      <Files className="w-4 h-4 text-cyber-accent" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">{f.filename}</p>
                      <p className="text-[11px] text-cyber-muted">
                        {formatBytes(f.size)} · {new Date(f.upload_date).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <span className="text-[10px] text-cyber-green font-mono bg-cyber-green/10
                                   px-2 py-1 rounded-md flex-shrink-0">
                    Encrypted
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
