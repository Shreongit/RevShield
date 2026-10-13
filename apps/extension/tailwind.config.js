/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./popup.html",
    "./options.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#0c0d0f',
        surface: {
          DEFAULT: '#131519',
          elevated: '#1a1d23',
          subtle: '#22262e',
        },
        border: {
          DEFAULT: '#232730',
          subtle: '#191c22',
        },
        text: {
          primary: '#f3f4f6',
          secondary: '#9ca3af',
          muted: '#6b7280',
        },
        accent: {
          DEFAULT: '#6366f1',
          hover: '#818cf8',
          subtle: '#1e1b4b',
        },
        shield: {
          safe: '#10b981',
          low: '#3b82f6',
          warning: '#f59e0b',
          danger: '#f43f5e',
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      }
    },
  },
  plugins: [],
}
