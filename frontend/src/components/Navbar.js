// =============================================================================
// components/Navbar.js — Top navigation bar
// =============================================================================
import { Menu, User, Bell } from 'lucide-react';

export default function Navbar({ user, onMenuToggle, pageTitle }) {
  return (
    <header className="sticky top-0 z-30 flex items-center justify-between
                        px-4 sm:px-8 h-16
                        bg-cyber-bg/80 backdrop-blur-xl
                        border-b border-white/[0.05]">
      {/* Left — menu + title */}
      <div className="flex items-center gap-4">
        <button
          onClick={onMenuToggle}
          className="btn-icon lg:hidden"
          aria-label="Toggle sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>
        <h2 className="text-lg font-semibold text-white hidden sm:block">
          {pageTitle}
        </h2>
      </div>

      {/* Right — notifications + user */}
      <div className="flex items-center gap-3">
        {/* Notification bell */}
        <button className="btn-icon relative" aria-label="Notifications">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full
                           bg-cyber-green animate-pulse" />
        </button>

        {/* User avatar */}
        <div className="flex items-center gap-3 pl-3 border-l border-white/[0.06]">
          <div className="w-9 h-9 rounded-full bg-gradient-to-br from-cyber-violet to-cyber-accent
                          flex items-center justify-center text-sm font-bold text-white shadow-lg">
            {(user?.email || 'U')[0].toUpperCase()}
          </div>
          <div className="hidden sm:block">
            <p className="text-sm font-medium text-white leading-tight">
              {user?.email || 'User'}
            </p>
            <p className="text-[11px] text-cyber-muted leading-tight">Secure account</p>
          </div>
        </div>
      </div>
    </header>
  );
}
