/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#0B0F19', // Primary surface
          800: '#111827', // Card surface
          700: '#1F2937', // Border / Muted
          600: '#374151',
          500: '#4B5563',
        },
        threat: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#3B82F6',
          info: '#10B981',
        },
        waf: {
          allow: '#10B981',
          block: '#EF4444',
          log: '#F59E0B',
          ratelimit: '#8B5CF6',
          cyan: '#06B6D4'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      }
    },
  },
  plugins: [],
}
