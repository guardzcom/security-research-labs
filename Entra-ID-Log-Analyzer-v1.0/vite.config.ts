// filename: vite.config.ts
import react from '@vitejs/plugin-react-swc';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';
import { resolve } from 'path';

// If you still want the phosphor icon import proxy but without Spark:
// The original createIconImportProxy came from @github/spark.
// We’ll skip it for now so dev runs clean. If the project relies on it,
// we can add a local plugin later or install the specific package.

const projectRoot = process.env.PROJECT_ROOT || new URL('.', import.meta.url).pathname;

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': resolve(projectRoot, 'src'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    host: true,
  },
  build: {
    outDir: 'dist',
    target: 'es2020',
    sourcemap: true,
  },
});
