// =============================================================================
// components/Sidebar.js — Navigation sidebar
// =============================================================================
import {
  LayoutDashboard,
  Upload,
  FolderOpen,
  Shield,
  LogOut,
  X,
  Cloud,
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard',   icon: LayoutDashboard },
  { id: 'upload',    label: 'Upload',      icon: Upload },
  { id: 'files',     label: 'My Files',    icon: FolderOpen },
];

export default function Sidebar({ activePage, setActivePage, onLogout, isOpen, onClose }) {
  return (
    <>
      {/* Backdrop (mobile) */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar panel */}
      <aside
        className={`
          fixed top-0 left-0 h-screen w-72 z-50
          bg-cyber-bg/95 backdrop-blur-2xl
          border-r border-white/[0.06]
          flex flex-col
          transition-transform duration-300 ease-out
          lg:translate-x-0 lg:static lg:z-auto
          ${isOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        {/* Brand */}
        <div className="flex items-center justify-between px-6 py-6 border-b border-white/[0.06]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyber-accent to-cyber-green
                            flex items-center justify-center shadow-lg shadow-cyber-accent/20">
              <Cloud className="w-5 h-5 text-cyber-bg" />
            </div>
            <div>
              <h1 className="text-lg font-bold gradient-text">SecureCloud</h1>
              <p className="text-[10px] text-cyber-muted font-medium tracking-wider uppercase">
                Zero-Knowledge Vault
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="btn-icon lg:hidden"
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto scrollbar-cyber">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
            const active = activePage === id;
            return (
              <button
                key={id}
                onClick={() => {
                  setActivePage(id);
                  onClose();
                }}
                className={`
                  w-full flex items-center gap-3 px-4 py-3 rounded-xl
                  text-sm font-medium transition-all duration-200
                  ${active
                    ? 'bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20 shadow-[0_0_20px_rgba(0,245,255,0.08)]'
                    : 'text-cyber-muted hover:text-white hover:bg-white/[0.04] border border-transparent'
                  }
                `}
              >
                <Icon className={`w-[18px] h-[18px] ${active ? 'text-cyber-accent' : ''}`} />
                {label}
              </button>
            );
          })}
        </nav>

        {/* Security badge */}
        <div className="px-4 pb-3">
          <div className="glass rounded-xl p-3 flex items-center gap-3">
            <Shield className="w-5 h-5 text-cyber-green flex-shrink-0" />
            <div>
              <p className="text-xs font-semibold text-cyber-green">AES-256 Protected</p>
              <p className="text-[10px] text-cyber-muted">End-to-end encrypted</p>
            </div>
          </div>
        </div>

        {/* Logout */}
        <div className="px-3 pb-5 pt-1">
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl
                       text-sm font-medium text-cyber-danger/80
                       hover:bg-cyber-danger/10 hover:text-cyber-danger
                       transition-all duration-200 border border-transparent
                       hover:border-cyber-danger/20"
          >
            <LogOut className="w-[18px] h-[18px]" />
            Sign Out
          </button>
        </div>
      </aside>
    </>
  );
}
