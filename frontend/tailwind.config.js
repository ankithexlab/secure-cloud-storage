/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50:  '#e6fffa',
          100: '#b2f5e8',
          200: '#81edd5',
          300: '#4fe5c2',
          400: '#00f5c4',
          500: '#00d4aa',
          600: '#00a888',
          700: '#007c66',
          800: '#005044',
          900: '#002422',
        },
        cyber: {
          bg:        '#0a0e17',
          surface:   '#111827',
          card:      '#1a1f2e',
          border:    '#1f2937',
          accent:    '#00f5ff',
          green:     '#00ff88',
          violet:    '#8b5cf6',
          pink:      '#ec4899',
          danger:    '#ff416c',
          text:      '#e0e7ff',
          muted:     '#94a3b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backdropBlur: {
        xs: '2px',
      },
      animation: {
        'fade-in':      'fadeIn 0.5s ease-out',
        'slide-up':     'slideUp 0.4s ease-out',
        'slide-down':   'slideDown 0.3s ease-out',
        'slide-right':  'slideRight 0.3s ease-out',
        'pulse-glow':   'pulseGlow 2s ease-in-out infinite',
        'spin-slow':    'spin 3s linear infinite',
        'float':        'float 6s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%':   { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          '0%':   { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideRight: {
          '0%':   { opacity: '0', transform: 'translateX(-20px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 20px rgba(0, 245, 255, 0.1)' },
          '50%':      { boxShadow: '0 0 40px rgba(0, 245, 255, 0.3)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%':      { transform: 'translateY(-10px)' },
        },
      },
    },
  },
  plugins: [],
}
