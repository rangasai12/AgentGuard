import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Backend (dashboard/server) serves /api/* (browser-facing Web API,
      // session-cookie authed). Proxying keeps dev same-origin so the
      // httpOnly ag_session cookie round-trips normally.
      '/api': {
        target: 'http://127.0.0.1:8090',
        changeOrigin: true,
      },
    },
  },
})
