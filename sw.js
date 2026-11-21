const CACHE_NAME = 'jireh-shell-v4';
const APP_SHELL = ['./manifest.webmanifest', './logo-jireh.svg'];
const offlineResponse = request => {
  const url = new URL(request.url);
  if (url.pathname.startsWith('/api/')) {
    return new Response(JSON.stringify({error: 'No hay conexión con el servidor. Intenta de nuevo.'}), {
      status: 503,
      headers: {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'}
    });
  }
  return new Response('No hay conexión con Encomienda Jireh. Revisa tu conexión e inténtalo de nuevo.', {
    status: 503,
    headers: {'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store'}
  });
};
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET' || new URL(request.url).origin !== self.location.origin) return;
  event.respondWith((async () => {
    try {
      const cached = await caches.match(request);
      return cached || await fetch(request);
    } catch (_) {
      return offlineResponse(request);
    }
  })().catch(() => offlineResponse(request)));
});
