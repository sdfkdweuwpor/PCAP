import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  // Relative asset URLs so the build works from any path (static hosting, artifact viewer).
  base: './',
  plugins: [react(), tailwindcss()],
  worker: { format: 'es' },
})
