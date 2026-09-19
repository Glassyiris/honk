const PREFIX = `doona-shell:${self.registration.scope}:`;
const CACHE = PREFIX + '68979febea819f7d';
const PRECACHE = ["assets/Config-iyEquJMK.js","assets/Connections-V8U0_oxq.js","assets/Dns-CcOFGkPj.js","assets/Events-DnNaeBuq.js","assets/Logs-Co1tWukS.js","assets/Nodes-BW14yCyO.js","assets/Overview-CM_vHD6i.js","assets/Policies-DeMnTaWi.js","assets/Rules-Cew56YL3.js","assets/index-CJeseAej.js","assets/index-Ct8DLfKq.css","assets/logo-obi05X1B.svg","assets/names-D35MwC4M.js","assets/vendor-aria-BEPq3xWb.js","assets/vendor-charts-D0IX8Chg.js","assets/vendor-editor-DdP9aXG2.js","assets/vendor-react-CY7D1GJF.js","index.html"];
const ROOT = new URL(self.registration.scope);

// A new build takes over on the next online load, including open dashboard tabs.
self.addEventListener('install', event => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});
self.addEventListener('activate', event => {
  event.waitUntil(
    caches
      .keys()
      .then(keys => Promise.all(keys.filter(key => key.startsWith(PREFIX) && key !== CACHE).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

function hit(response) {
  if (!response) return Response.error();
  const headers = new Headers(response.headers);
  headers.set('x-doona-sw', 'hit');
  return new Response(response.body, {status: response.status, statusText: response.statusText, headers});
}

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== ROOT.origin || /\/api(?:\/|$)/.test(url.pathname) || !url.pathname.startsWith(ROOT.pathname)) return;
  const navigation = request.mode === 'navigate';
  if (!navigation && !/^(assets|fonts|icons)\//.test(url.pathname.slice(ROOT.pathname.length))) return;
  event.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      if (navigation) {
        try {
          return await fetch(request);
        } catch {
          return hit(await cache.match(new URL('index.html', ROOT)));
        }
      }
      const response = await cache.match(request);
      if (response) return hit(response);
      const fresh = await fetch(request);
      if (fresh.ok && fresh.type === 'basic' && !fresh.redirected) await cache.put(request, fresh.clone());
      return fresh;
    })()
  );
});
