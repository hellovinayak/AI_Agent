/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#0a0e1a',
          surface: '#111827',
          'surface-light': '#1f2937',
          accent: {
            red: '#ef4444',
            orange: '#f97316',
            amber: '#f59e0b',
            blue: '#3b82f6',
            purple: '#8b5cf6',
            green: '#10b981',
          },
          text: '#e5e7eb',
          'text-dim': '#9ca3af',
          border: 'rgba(255,255,255,0.08)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
};
