import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

const backendHost = process.env.AGENT_SUPERVISOR_API_HOST || '127.0.0.1';
const backendPort = Number(process.env.AGENT_SUPERVISOR_API_PORT || '8012');

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    exclude: ['e2e/**', '**/node_modules/**', '**/dist/**'],
    // Ant Design's jsdom-heavy gateway and evidence views routinely need
    // several seconds to mount when the full suite is loaded together. Keep
    // the timeout bounded, but leave enough headroom for a cold Windows
    // checkout instead of making file scheduling change the result.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Each file has its own jsdom/module sandbox. Running independent files
    // concurrently prevents a serial worker from carrying expensive timers
    // and DOM work into the next file, which previously caused false timeout
    // failures in the full suite while the same tests passed in isolation.
    fileParallelism: true,
    maxWorkers: 4
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          const normalizedId = id.replaceAll('\\', '/');
          if (!normalizedId.includes('node_modules')) {
            return undefined;
          }
          if (
            normalizedId.includes('/react/') ||
            normalizedId.includes('/react-dom/') ||
            normalizedId.includes('/scheduler/')
          ) {
            return 'vendor-react';
          }
          if (normalizedId.includes('/antd/')) {
            return 'vendor-antd';
          }
          if (normalizedId.includes('/@ant-design/icons') || normalizedId.includes('/lucide-react/')) {
            return 'vendor-icons';
          }
          return 'vendor-ui-support';
        }
      }
    }
  },
  server: {
    port: 5178,
    proxy: {
      '/api': `http://${backendHost}:${backendPort}`,
      // The console submits real OpenAI-compatible requests from the same
      // origin.  Without this route development mode sent /v1 requests to
      // Vite itself and produced a misleading 404 even while the API was
      // healthy.
      '/v1': `http://${backendHost}:${backendPort}`
    }
  }
});
