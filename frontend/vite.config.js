import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

const resolveProxyTarget = (env) => {
  const explicitTarget = String(env.VITE_DEV_PROXY_TARGET || '').trim()
  if (explicitTarget) return explicitTarget

  const apiBase = String(env.VITE_API_BASE || '').trim()
  if (apiBase) {
    try {
      return new URL(apiBase).origin
    } catch {
      // Fall through to the standard Docker service target when the env var is relative.
    }
  }

  return 'http://backend:8000'
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  const proxyTarget = resolveProxyTarget(env)

  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0',
      port: 5173,
      watch: {
        usePolling: true  // Better for Docker
      },
      proxy: {
        '/api': {
          target: proxyTarget,
          ws: true,
          rewriteWsOrigin: true,
          changeOrigin: true
        },
        '/ops': {
          target: proxyTarget,
          changeOrigin: true
        },
        '/docs': {
          target: proxyTarget,
          changeOrigin: true
        },
        '/openapi.json': {
          target: proxyTarget,
          changeOrigin: true
        },
        '/redoc': {
          target: proxyTarget,
          changeOrigin: true
        },
        '/ws': {
          target: proxyTarget,
          ws: true,
          rewriteWsOrigin: true,
          changeOrigin: true
        }
      }
    },
    // Disable experimental features that use rolldown
    experimental: {
      renderBuiltUrl: undefined
    },
    build: {
      rollupOptions: {}  // Use Rollup instead of Rolldown
    }
  }
})
