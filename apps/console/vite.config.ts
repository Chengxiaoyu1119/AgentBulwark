import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import net from 'node:net';
import { fileURLToPath, URL } from 'node:url';
import type { Plugin, ViteDevServer } from 'vite';

const backendHost = process.env.AGENT_SUPERVISOR_API_HOST || '127.0.0.1';
const backendPort = Number(process.env.AGENT_SUPERVISOR_API_PORT || '8012');

function isBackendOnline(timeoutMs = 250) {
  return new Promise<boolean>((resolve) => {
    const socket = net.createConnection({ host: backendHost, port: backendPort });
    let settled = false;
    const finish = (online: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(online);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

function backendHealthFallbackPlugin(): Plugin {
  return {
    name: 'agent-supervisor-api-health-fallback',
    configureServer(server: ViteDevServer) {
      server.middlewares.use('/api/health', async (request, response, next) => {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          next();
          return;
        }
        if (await isBackendOnline()) {
          next();
          return;
        }
        response.statusCode = 200;
        response.setHeader('Content-Type', 'application/json; charset=utf-8');
        response.end(JSON.stringify({ ok: false, service: 'agent-security-supervisor', offline: true }));
      });
    }
  };
}

export default defineConfig({
  plugins: [backendHealthFallbackPlugin(), react()],
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
    // several seconds to mount when the full suite is loaded together.  The
    // previous five-second default made the same tests pass in isolation but
    // fail under the normal repository verification command.  Keep the
    // timeout bounded while making the result independent of file scheduling.
    testTimeout: 15_000,
    hookTimeout: 15_000,
    fileParallelism: false
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
