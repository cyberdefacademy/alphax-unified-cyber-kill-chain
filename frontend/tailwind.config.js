/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ['class', '[data-theme="neon"]', '[data-theme="tactical"]', '[data-theme="crimson"]', '[data-theme="midnight"]'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      colors: {
        alphax: { bg: "#060a12", panel: "#0f172a", accent: "#22d3ee", danger: "#f43f5e", success: "#22c55e" }
      }
    }
  },
  plugins: []
}
