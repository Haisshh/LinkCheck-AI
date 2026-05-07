import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  // IMPORTANT: '/' not './'
  // './' generates relative paths like src="./assets/index.js" 
  // '/' generates absolute paths like src="/assets/index.js" 
  base: '/',

  build: {
    outDir: '../static/frontend',
    emptyOutDir: true,
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name].js',
        chunkFileNames:  'assets/[name].js',
        assetFileNames:  'assets/[name].[ext]',
      },
    },
  },

  server: {
    port: 5173,
    proxy: {
      '/analyze':    { target: 'http://localhost:5000', changeOrigin: true },
      '/api':        { target: 'http://localhost:5000', changeOrigin: true },
      '/feedback':   { target: 'http://localhost:5000', changeOrigin: true },
      '/screenshot': { target: 'http://localhost:5000', changeOrigin: true },
    },
  },
});
