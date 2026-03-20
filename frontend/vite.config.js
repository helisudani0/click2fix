import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    watch: {
      usePolling: true  // Better for Docker
    },
    proxy: {
      '/api': {
        target: 'http://c2f-lb:8000',
        changeOrigin: true
      },
      '/ops': {
        target: 'http://c2f-lb:8000',
        changeOrigin: true
      },
      '/docs': {
        target: 'http://c2f-lb:8000',
        changeOrigin: true
      },
      '/openapi.json': {
        target: 'http://c2f-lb:8000',
        changeOrigin: true
      },
      '/redoc': {
        target: 'http://c2f-lb:8000',
        changeOrigin: true
      },
      '/ws': {
        target: 'http://c2f-lb:8000',
        ws: true,
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
})
