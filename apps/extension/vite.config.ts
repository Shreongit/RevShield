import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';

function copyManifestPlugin() {
  return {
    name: 'copy-manifest',
    closeBundle() {
      const manifestSrc = path.resolve(__dirname, 'manifest.json');
      const manifestDest = path.resolve(__dirname, 'dist', 'manifest.json');
      if (fs.existsSync(manifestSrc)) {
        fs.copyFileSync(manifestSrc, manifestDest);
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), copyManifestPlugin()],
  publicDir: 'public',
  resolve: {
    alias: {
      '@webshield/shared-types': path.resolve(__dirname, '../../packages/shared-types'),
      '@webshield/shared-utils': path.resolve(__dirname, '../../packages/shared-utils'),
      '@webshield/rule-engine': path.resolve(__dirname, '../../packages/rule-engine'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    rollupOptions: {
      input: {
        popup: path.resolve(__dirname, 'popup.html'),
        options: path.resolve(__dirname, 'options.html'),
        background: path.resolve(__dirname, 'src/background/service_worker.ts'),
        content: path.resolve(__dirname, 'src/content/content_script.ts'),
      },
      output: {
        entryFileNames: 'src/[name]/[name].js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name].[ext]',
      },
    },
  },
});
