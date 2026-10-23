// Meikova Auth — PWA Offline Service Worker
const CACHE_NAME = 'meikova-auth-shell-v1';
const STATIC_ASSETS = [
  '/',
  '/dashboard',
  '/login',
  '/static/index.html',
  '/static/sso.html',
  '/static/brand-identity.json',
  '/static/site.webmanifest',
  '/static/logo.svg',
  '/static/favicon.svg',
  '/static/favicon-32.png',
  '/static/apple-touch-icon.png',
  '/static/icon-any-192.png',
  '/static/icon-any-512.png',
  '/static/icon-maskable-192.png',
  '/static/icon-maskable-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[SW Install Warning] Asset pre-cache failed:', err);
      });
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Network-first for all /api endpoints
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/health')) {
    event.respondWith(
      fetch(event.request).catch(() => {
        return new Response(JSON.stringify({ error: 'Offline', offline: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }

  // Cache-first falling back to network for shell assets
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        if (response.status === 200 && event.request.method === 'GET') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        }
        return response;
      });
    }).catch(() => {
      if (event.request.headers.get('accept')?.includes('text/html')) {
        return caches.match('/static/index.html');
      }
    })
  );
});
