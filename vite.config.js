import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Esto hace que /api en el frontend apunte a nuestro servidor local
      '/api': {
        // IPv4 explícito: server.js escucha solo en 127.0.0.1 (por diseño, para no
        // exponer la API de gestión a la red) y 'localhost' puede resolver primero
        // a ::1 en Windows, lo que hace fallar el proxy en seco.
        target: 'http://127.0.0.1:3001',
        changeOrigin: true,
      }
    }
  }
})
