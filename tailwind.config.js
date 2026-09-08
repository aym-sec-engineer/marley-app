/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html'
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'cyber-bg': '#06080f',
        'cyber-surface': '#0d1220',
        'cyber-surface-2': '#161d2e',
        'cyber-border': 'rgba(148, 163, 184, 0.08)',
        'cyber-border-strong': 'rgba(148, 163, 184, 0.16)',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'sans-serif'],
        sans: ['Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
};
