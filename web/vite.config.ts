import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// The websocket handler accepts same-origin connections only, so in
// development everything goes through this proxy rather than straight at
// :8090. Pointing the client at the server's own port instead would be
// cross-origin and refused at the upgrade — before any error the app could
// report.
/**
 * The development server injects its stylesheets as <style> elements written by
 * script, which the page's own content security policy refuses — leaving `npm
 * run dev` rendering an unstyled document.
 *
 * Relaxed here and only here: `apply: 'serve'` means this never touches a
 * build, so the file the server ships keeps the strict policy. That policy is
 * not decoration — the archive private key lives in this page.
 */
const devStyles = {
  name: 'dev-style-src',
  apply: 'serve' as const,
  transformIndexHtml(html: string) {
    return html.replace("default-src 'self';", "default-src 'self'; style-src 'self' 'unsafe-inline';")
  },
}

export default defineConfig({
  plugins: [vue(), devStyles],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)), '@subscription': fileURLToPath(new URL(process.env.WAPPIE_CLOUD_BUILD === '1' ? '../commercial/SubscriptionPanel.vue' : './src/components/SubscriptionPanel.vue', import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      '/v1': {
        target: process.env.WS_DEV_TARGET ?? 'http://localhost:8090',
        changeOrigin: false,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    environment: 'node',
    include: ['test/**/*.spec.ts'],
  },
})
