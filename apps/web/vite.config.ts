import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@webshield/shared-types': path.resolve(__dirname, '../../packages/shared-types'),
      '@webshield/shared-utils': path.resolve(__dirname, '../../packages/shared-utils'),
      '@webshield/rule-engine': path.resolve(__dirname, '../../packages/rule-engine'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
