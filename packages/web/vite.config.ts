import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Built assets are served by the traceglass CLI from this package's dist dir.
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    // Dev convenience: proxy API calls to a locally-running `traceglass open`.
    proxy: {
      '/api': 'http://127.0.0.1:4317',
    },
  },
});
