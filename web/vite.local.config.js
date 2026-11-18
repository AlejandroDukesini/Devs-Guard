// Build of the local web app served by `depguard serve` (dep_guard/server).
// Output goes inside the Python package so the wheel ships the interface.
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const here = (path) => fileURLToPath(new URL(path, import.meta.url))

export default defineConfig({
  plugins: [react(), tailwindcss()],
  publicDir: false,
  build: {
    target: 'es2022',
    sourcemap: false,
    outDir: here('../dep_guard/server/static'),
    emptyOutDir: true,
    rollupOptions: { input: here('./local.html') },
  },
})
