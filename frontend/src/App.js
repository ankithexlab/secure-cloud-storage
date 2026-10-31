// =============================================================================
// App.js — Root application component
// =============================================================================
import { useEffect, useState, useCallback } from 'react';
import { AlertCircle } from 'lucide-react';
import toast from 'react-hot-toast';
import './index.css';

// Components
import ToastProvider from './components/Toast';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';

// Pages
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import UploadPage from './pages/UploadPage';
import FilesPage from './pages/FilesPage';

// API
import { getFiles, healthCheck } from './services/api';
import { API_BASE_URL } from './api';


const PAGE_TITLES = {
  dashboard: 'Dashboard',
  upload: 'Secure Upload',
  files: 'My Files',
};

function App() {
  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState('');

  // UI state
  const [activePage, setActivePage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Data state
  const [files, setFiles] = useState([]);
  const [stats, setStats] = useState({ total_files: 0, total_size: 0 });
  const [filesLoading, setFilesLoading] = useState(false);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [backendUrl, setBackendUrl] = useState(API_BASE_URL);


  // ---------------------------------------------------------------------------
  // Restore session from localStorage
  // ---------------------------------------------------------------------------
  // Health check
  useEffect(() => {
    healthCheck().then((status) => {
      setBackendStatus(status.ok ? 'healthy' : 'offline');
      if (status.backendUrl) {
        setBackendUrl(status.backendUrl);
      }
    });
  }, []);

  useEffect(() => {
    const savedToken = localStorage.getItem('sc_token');
    const savedUser = localStorage.getItem('sc_user');
    if (savedToken && savedUser) {
      try {
        const parsed = JSON.parse(savedUser);
        setToken(savedToken);
        setUser(parsed);
        setIsLoggedIn(true);
      } catch {
        localStorage.removeItem('sc_token');
        localStorage.removeItem('sc_user');
      }
    }
  }, []);


  // ---------------------------------------------------------------------------
  // Fetch files
  // ---------------------------------------------------------------------------
  const refreshFiles = useCallback(async () => {
    if (!token) return;
    setFilesLoading(true);
    try {
      const res = await getFiles(token);
      if (res.ok) {
        setFiles(res.data?.files || []);
        setStats(res.data?.stats || { total_files: 0, total_size: 0 });
      } else if (res.status === 401) {
        toast.error('Session expired. Please login again.');
        setIsLoggedIn(false);
        setToken('');
        setUser(null);
        setFiles([]);
        setStats({ total_files: 0, total_size: 0 });
        setActivePage('dashboard');
        setSidebarOpen(false);
        localStorage.removeItem('sc_token');
        localStorage.removeItem('sc_user');
      } else {
        toast.error(res.data?.msg || 'Failed to load files');
      }
    } catch (err) {
      console.error('Failed to fetch files:', err);
      toast.error('Failed to load files');
    } finally {
      setFilesLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (isLoggedIn && token) {
      refreshFiles();
    }
  }, [isLoggedIn, token, refreshFiles]);

  // ---------------------------------------------------------------------------
  // Auth handlers
  // ---------------------------------------------------------------------------
  const handleLogin = (data) => {
    const { token: t, user: u } = data;
    setToken(t);
    setUser(u);
    setIsLoggedIn(true);
    localStorage.setItem('sc_token', t);
    localStorage.setItem('sc_user', JSON.stringify(u));
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setToken('');
    setUser(null);
    setFiles([]);
    setStats({ total_files: 0, total_size: 0 });
    setActivePage('dashboard');
    setSidebarOpen(false);
    localStorage.removeItem('sc_token');
    localStorage.removeItem('sc_user');
  };

  // ---------------------------------------------------------------------------
  // Not logged in → Login page
  // ---------------------------------------------------------------------------
  if (backendStatus === 'offline') {
    return (
      <>
        <ToastProvider />
        <div className="min-h-screen flex items-center justify-center p-8">
          <div className="glass p-8 text-center max-w-md">
            <AlertCircle className="w-16 h-16 text-cyber-danger mx-auto mb-6" />
            <h1 className="text-2xl font-bold text-white mb-4">Backend Offline</h1>
            <p className="text-cyber-muted mb-6">
              Cannot connect to API server at <strong>{backendUrl}</strong>
            </p>
            <div className="space-y-2 text-sm text-cyber-muted mb-8">
              <p>• Backend server not running</p>
              <p>• Check MongoDB is running</p>
              <p>• Run: <code>cd backend && python app.py</code></p>
            </div>
            <button
              onClick={() => window.location.reload()}
              className="btn-primary w-full py-3"
            >
              Retry Connection
            </button>
          </div>
        </div>
      </>
    );
  }

  if (!isLoggedIn) {
    return (
      <>
        <ToastProvider />
        <LoginPage onLogin={handleLogin} backendStatus={backendStatus} />
      </>
    );
  }


  // ---------------------------------------------------------------------------
  // Logged in → Dashboard layout
  // ---------------------------------------------------------------------------
  const renderPage = () => {
    switch (activePage) {
      case 'upload':
        return (
          <UploadPage
            token={token}
            onUploadComplete={refreshFiles}
          />
        );
      case 'files':
        return (
          <FilesPage
            files={files}
            loading={filesLoading}
            token={token}
            onRefresh={refreshFiles}
            setActivePage={setActivePage}
          />
        );
      case 'dashboard':
      default:
        return (
          <DashboardPage
            stats={stats}
            files={files}
            setActivePage={setActivePage}
          />
        );
    }
  };

  return (
    <>
      <ToastProvider />
      <div className="flex min-h-screen">
        <Sidebar
          activePage={activePage}
          setActivePage={setActivePage}
          onLogout={handleLogout}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />
        <div className="flex-1 flex flex-col min-h-screen lg:ml-0">
          <Navbar
            user={user}
            pageTitle={PAGE_TITLES[activePage] || 'Dashboard'}
            onMenuToggle={() => setSidebarOpen(!sidebarOpen)}
          />
          <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto scrollbar-cyber">
            {renderPage()}
          </main>
        </div>
      </div>
    </>
  );
}

export default App;
