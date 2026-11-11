import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '::',
    port: 5173,
    warmup: {
      clientFiles: [
        './src/pages/Login.jsx',
        './src/pages/Dashboard.jsx',
        './src/pages/AdminDashboard.jsx',
        './src/pages/Cases.jsx',
        './src/pages/Evidence.jsx',
        './src/pages/Upload.jsx',
        './src/pages/Agents.jsx'
      ]
    }
  }
})
