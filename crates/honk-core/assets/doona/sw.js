const PREFIX = `doona-shell:${self.registration.scope}:`;
const CACHE = PREFIX + '6a7986abfac719a1';
const PRECACHE = ["assets/ActionGroup-BrBnwrm_.js","assets/AddCircle-5Q31Nu-B.js","assets/AreaChart-Dikw9tL9.js","assets/AreaCurve-BriPYJva.js","assets/Arrange-B7RmL3AG.js","assets/Arrange-Dd3j3leY.css","assets/Config-x4YtnuK0.js","assets/Connections-dYXN7ZlF.js","assets/Coverage-ClwVoz2v.js","assets/DaeCode-B8yPDjSE.js","assets/Dns-DmYYBYA4.js","assets/Donut-Ce8JOGj2.js","assets/Events-BiwwBnCK.js","assets/FactStrip-DPa_HtBm.js","assets/Flows-BgMILIC1.js","assets/Flows-l5FnUA9B.css","assets/ListLayout-CwAbnzUO.js","assets/Login-CQrLeYwX.js","assets/LoginShowcase-CXoile1-.js","assets/Logs-DYRowBdU.js","assets/NodeSearch-DQmlfd0x.js","assets/Nodes-CW-Ex7wB.js","assets/Overview-C9SiR5mN.js","assets/Policies-CKmiWYW9.js","assets/Rules-jgwnwX-h.js","assets/SearchDialog-BtnJh1PQ.js","assets/Settings-BQcZDYWE.js","assets/Sparkline-B1dDV8Bn.js","assets/Table-CwANdxJF.js","assets/TimeCell-BF4c2JOk.js","assets/Virtualizer-bLaTwOUL.js","assets/array-C0P64tl-.js","assets/auth-CoJmUGPx.js","assets/auth-Df3CuwX8.js","assets/dns-B0p_7B-V.js","assets/duck-night-CbKHyiul.webp","assets/files-BxEOxSF8.js","assets/flows-xJ8iEXlb.js","assets/geodata-De9_qBkH.js","assets/index-7R3bVGRM.css","assets/index-CZX-07a6.js","assets/labels-Bgu_ZhL8.js","assets/layout-DgqFnsE3.js","assets/logo-obi05X1B.svg","assets/nav-BASDWt23.js","assets/nav-BDuOAxcR.js","assets/nav-BFiTWnsa.js","assets/nav-BmMnuElE.js","assets/nav-BxAD_M-O.js","assets/nav-Cpci9QWe.js","assets/nav-D5WY5Qjf.js","assets/nav-Wiib71Wo.js","assets/openGroup-BmnppsBj.js","assets/outbounds-CRpItEsE.js","assets/policyText-DQzr_nC9.js","assets/probe-Cwt0keuU.js","assets/qiangguo-gorges-dark-FlgXSNn1.webp","assets/qiangguo-gorges-light-DCWkLX37.webp","assets/qiangguo-lake-dark-B_VaUlAe.webp","assets/qiangguo-lake-light-oWll36-V.webp","assets/qiangguo-square-dark-CG0rwsS1.webp","assets/qiangguo-square-light-OU6dsCf9.webp","assets/qiangguo-taishan-dark-BI3cd4fj.webp","assets/qiangguo-taishan-light-Dip0HmJZ.webp","assets/qiangguo-wall-dark-DCO0xUUO.webp","assets/qiangguo-wall-light-BYfte2Bi.webp","assets/ranked-D43xh_Jl.js","assets/recorder-DlDpPhd4.js","assets/setup-Ds5K5C5X.js","assets/useFilter-BMwJMcdF.js","assets/useGridSelectionCheckbox-oCK7e6Rr.js","assets/useQuickRule-D9gCRsmu.js","assets/useRefreshAll-Bd-G-05P.js","assets/vendor-editor-2EGeBPxF.js","assets/vendor-react-Bf71BWbF.js","index.html"];
// Each language's catalogue and stylesheets in this build, cached only for a language a reader uses. A partial
// language's list holds the reference language's files too, since it loads them.
const LANGUAGES = {"zh-TW":["assets/fonts-tc-B6Zt5HQN.css","assets/locale-zh-TW-CjV1NjVp.js"],"zh-CN":["assets/fonts-sc-DWPGxLPK.css","assets/locale-zh-CN-DF_91JnF.js"],"en":["assets/locale-en-B_WE0vC5.js"]};
// The mock backend's chunk, cached only for a page that runs on it.
const MOCK = ["assets/index-CbSTNKjG.js"];
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
// A page loads its catalogue and backend before this worker controls it, so it reports the language it shows and
// whether it runs on the mock, to have them cached.
self.addEventListener('message', event => {
  const lang = event.data?.language;
  const files = [...(typeof lang === 'string' && Object.hasOwn(LANGUAGES, lang) ? LANGUAGES[lang] : []), ...(event.data?.mock === true ? MOCK : [])];
  if (!files.length) return;
  event.waitUntil(caches.open(CACHE).then(cache => Promise.all(files.map(async url => (await cache.match(url, {ignoreVary: true})) ?? cache.add(url)))));
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
