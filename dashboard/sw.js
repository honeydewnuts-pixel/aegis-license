const CACHE = "aegis-dash-shell-v1";
const SHELL = ["/dashboard/", "/dashboard/index.html", "/dashboard/styles.css", "/dashboard/app.js", "/dashboard/manifest.webmanifest", "/dashboard/icon.svg"];
self.addEventListener("install", function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }));
});
self.addEventListener("fetch", function (e) {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/api/")) return;
  e.respondWith(
    caches.match(e.request).then(function (cached) {
      return cached || fetch(e.request);
    })
  );
});
