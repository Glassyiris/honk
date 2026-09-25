const PREFIX = `doona-shell:${self.registration.scope}:`;
const CACHE = PREFIX + '3c574bb09128b5d2';
const PRECACHE = ["assets/Arrange-B2EsCycg.js","assets/Config-DNrHmV_s.js","assets/Connections-MW8lex31.js","assets/Dns-CeKZ0OKA.js","assets/Events-CDWszmsc.js","assets/Lifecycle-C8bF8LmW.js","assets/Login-BKmnYiUp.js","assets/Logs-DluHZ3AW.js","assets/Nodes-B9MamIES.js","assets/Overview-HGQ-odRJ.js","assets/Policies-Ctv3Hdi5.js","assets/PolicyPicker-B0IYDSNz.js","assets/Rules-BLjxjhO2.js","assets/SearchDialog-B45FEjU6.js","assets/Settings-DtnnyQuN.js","assets/Table-BdSFV9jo.js","assets/TimeCell-CbIEVvIf.js","assets/auth-Dvie0grX.js","assets/dns-C___Rd4S.js","assets/duck-night-CbKHyiul.webp","assets/files-BxEOxSF8.js","assets/index-BWDo9u7j.css","assets/index-Bk3oKdvG.js","assets/index-Cfspjh03.js","assets/layout--PvBvvCO.js","assets/link-fi2kv7ab.js","assets/logo-obi05X1B.svg","assets/names-D7Aa1Gga.js","assets/outbounds-CS2qjFRk.js","assets/query-CooI-_z8.js","assets/setup-CM9vnbAa.js","assets/useGridSelectionCheckbox-CURbcoLm.js","assets/vendor-charts-BSOgcWus.js","assets/vendor-editor-BYSNX95r.js","assets/vendor-react-Ey0dazfG.js","assets/view-8dZ9FUEp.js","assets/view-BY4tMdGa.js","assets/view-CeOG7rPl.js","assets/view-RJ2xeb5a.js","assets/view-i8VCwUqE.js","assets/vocab-BfgnwTNm.js","index.html"];
// Each language's catalogue and stylesheets in this build, cached only for a language a reader uses.
const LANGUAGES = {"zh-CN":["assets/fonts-sc-DWPGxLPK.css","assets/locale-zh-CN-CU2xf3QZ.js"],"zh-TW":["assets/fonts-tc-B6Zt5HQN.css","assets/locale-zh-TW-w6n_EnQ6.js"],"en":["assets/locale-en-ETYyIPe0.js"]};
const ROOT = new URL(self.registration.scope);

// A new build takes over on the next online load, including open dashboard tabs.
// Each build records when it was installed, so activation can tell the build it replaces from older ones.
const STAMP = new URL('__installed__', ROOT);
// Fetched past the HTTP cache, so a caching proxy cannot hand the new build an old shell.
self.addEventListener('install', event => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then(cache => Promise.all([cache.addAll(PRECACHE.map(url => new Request(url, {cache: 'reload'}))), cache.put(STAMP, new Response(String(Date.now())))]))
      .then(() => self.skipWaiting())
  );
});
// A page loads its catalogue before this worker controls it, so it reports the language it shows to have it cached.
self.addEventListener('message', event => {
  const lang = event.data?.language;
  if (typeof lang !== 'string' || !Object.hasOwn(LANGUAGES, lang)) return;
  event.waitUntil(
    caches.open(CACHE).then(cache => Promise.all(LANGUAGES[lang].map(async url => (await cache.match(url, {ignoreVary: true})) ?? cache.add(url))))
  );
});
// The build just replaced stays: tabs still showing it load their remaining chunks from it until reloaded.
self.addEventListener('activate', event => {
  event.waitUntil(
    (async () => {
      const older = [];
      for (const key of await caches.keys()) {
        if (!key.startsWith(PREFIX) || key === CACHE) continue;
        const stamp = await (await caches.open(key)).match(STAMP);
        older.push({key, installed: stamp ? Number(await stamp.text()) : 0});
      }
      older.sort((a, b) => b.installed - a.installed);
      await Promise.all(older.slice(1).map(({key}) => caches.delete(key)));
      await self.clients.claim();
    })()
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
      // A build file is the same for every requester, so a server's Vary: Origin must not turn a cached copy into a miss.
      const response = (await cache.match(request, {ignoreVary: true})) ?? (await caches.match(request, {ignoreVary: true}));
      if (response) return hit(response);
      const fresh = await fetch(request);
      if (fresh.ok && fresh.type === 'basic' && !fresh.redirected) await cache.put(request, fresh.clone());
      return fresh;
    })()
  );
});
