/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        alphax: { bg: "#060a12", panel: "#0f172a", accent: "#22d3ee", danger: "#f43f5e", success: "#22c55e" }
      }
    }
  },
  plugins: []
}
