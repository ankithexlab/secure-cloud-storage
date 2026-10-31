// =============================================================================
// pages/LoginPage.js — Authentication (Login / Register)
// =============================================================================
import { useState } from 'react';
import { Eye, EyeOff, Lock, Mail, Cloud, Shield, ArrowRight, Loader2 } from 'lucide-react';
import toast from 'react-hot-toast';
import { loginRequest, registerRequest } from '../services/api';
import { API_BASE_URL } from '../api';

export default function LoginPage({ onLogin }) {
  const [isSignup, setIsSignup] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});

  // ---------------------------------------------------------------------------
  // Validation
  // ---------------------------------------------------------------------------
  const validate = () => {
    const e = {};
    const trimmedEmail = email.trim();
if (!trimmedEmail) e.email = 'Fields cannot be empty';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) e.email = 'Invalid email';
    
if (!password) {
  e.password = 'Fields cannot be empty';
} else {
if (password.length < 6) e.password = 'Password too short';
      else if (!/\d/.test(password)) e.password = 'Password must contain at least 1 number';
    }

    if (isSignup) {
      if (password !== confirmPassword) {
        e.confirmPassword = 'Passwords do not match';
      }
    }
    
    return e;
  };

  // ---------------------------------------------------------------------------
  // Submit
  // ---------------------------------------------------------------------------
  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    setErrors(errs);
    if (Object.keys(errs).length) return;

    setLoading(true);
    try {
      const fn = isSignup ? registerRequest : loginRequest;
      const res = await fn({ email: email.trim().toLowerCase(), password });

if (!res.ok) {
      let errorMsg = 'Login failed';
      if (res.status === 401) {
        errorMsg = 'Invalid credentials';
      } else if (res.status === 0 || !res.status) {
        errorMsg = `Server not reachable at ${API_BASE_URL}`;
      } else {
        errorMsg = res.data?.error || res.data?.msg || 'Request failed';
      }
      toast.error(errorMsg);
      setLoading(false);
      return;
    }

      toast.success(isSignup ? 'Account created!' : 'Welcome back!');
      onLogin(res.data);
} catch (err) {
      console.error("Backend connection error:", err);
      let msg = 'Network error - backend unreachable';
      if (err.name === 'TypeError') {
        msg = `Cannot reach backend at ${API_BASE_URL}. Check server running (python app.py)`;
      } else {
        msg = err.message || msg;
      }
      toast.error(msg);

    }
    setLoading(false);
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-8 relative overflow-hidden">
      {/* Decorative background circles */}
      <div className="absolute top-1/4 -left-32 w-96 h-96 rounded-full
                      bg-cyber-accent/5 blur-3xl animate-float" />
      <div className="absolute bottom-1/4 -right-32 w-96 h-96 rounded-full
                      bg-cyber-violet/5 blur-3xl animate-float"
           style={{ animationDelay: '3s' }} />

      <div className="w-full max-w-md animate-fade-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl
                          bg-gradient-to-br from-cyber-accent to-cyber-green
                          shadow-xl shadow-cyber-accent/20 mb-4">
            <Cloud className="w-8 h-8 text-cyber-bg" />
          </div>
          <h1 className="text-3xl font-bold gradient-text mb-1">
            {isSignup ? 'Create Account' : 'Welcome Back'}
          </h1>
          <p className="text-cyber-muted text-sm">
            {isSignup ? 'Join the zero-knowledge revolution' : 'Sign in to access your secure vault'}
          </p>
        </div>

        {/* Card */}
        <div className="glass p-8 animate-slide-up">
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email */}
            <div>
              <label className="block text-xs font-medium text-cyber-muted mb-2 uppercase tracking-wider">
                Email address
              </label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  disabled={loading}
                  className="input-field pl-11"
                  autoComplete="email"
                />
              </div>
              {errors.email && (
                <p className="mt-1.5 text-xs text-cyber-danger animate-slide-down">{errors.email}</p>
              )}
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-medium text-cyber-muted mb-2 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  disabled={loading}
                  className="input-field pl-11 pr-12"
                  autoComplete={isSignup ? 'new-password' : 'current-password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded-lg
                             text-cyber-muted hover:text-cyber-accent transition-colors"
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1.5 text-xs text-cyber-danger animate-slide-down">{errors.password}</p>
              )}
            </div>

            {/* Confirm Password (Signup only) */}
            {isSignup && (
              <div className="animate-slide-down">
                <label className="block text-xs font-medium text-cyber-muted mb-2 uppercase tracking-wider">
                  Confirm Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••"
                    disabled={loading}
                    className="input-field pl-11 pr-12"
                    autoComplete="new-password"
                  />
                </div>
                {errors.confirmPassword && (
                  <p className="mt-1.5 text-xs text-cyber-danger animate-slide-down">{errors.confirmPassword}</p>
                )}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full py-3.5 text-base mt-2"
            >
              {loading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <>
                  {isSignup ? 'Create Account' : 'Sign In'}
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Security note */}
          <div className="mt-6 flex items-center justify-center gap-2 text-xs text-cyber-muted">
            <Shield className="w-3.5 h-3.5 text-cyber-green" />
            <span>End-to-end encrypted &middot; Zero-knowledge</span>
          </div>

          {/* Toggle Mode */}
          <div className="mt-6 text-center text-sm text-cyber-muted">
            {isSignup ? "Already have an account? " : "Don't have an account? "}
            <button
              type="button"
              onClick={() => {
                setIsSignup(!isSignup);
                setErrors({});
                setConfirmPassword('');
              }}
              className="text-cyber-accent hover:text-white transition-colors font-semibold"
            >
              {isSignup ? 'Sign In' : 'Create Account'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
