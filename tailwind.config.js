/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './static/js/**/*.js'
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'cyber-bg': '#0a0d12',
        'cyber-surface': '#10141b',
        'cyber-surface-2': '#151a23',
        'cyber-border': 'rgba(148, 163, 184, 0.10)',
        'cyber-border-strong': 'rgba(148, 163, 184, 0.18)',
      },
      fontFamily: {
        display: ['Inter', 'sans-serif'],
        sans: ['Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
};
