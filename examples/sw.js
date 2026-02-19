/**
 * Meow Decoder - Service Worker for Caching
 *
 * Caches WASM modules and static assets for instant loading on repeat visits.
 * This is a performance optimization only - no crypto operations happen here.
 */

const CACHE_NAME = 'meow-decoder-v2';

// Assets to cache on install
const PRECACHE_ASSETS = [
    './',
    './index.html',
    './crypto-worker.js',
    './crypto_core.js',
    './crypto_core_bg.wasm',
    './assets/meow-decoder-logo.svg'
];

// Install event - cache critical assets
self.addEventListener('install', (event) => {
    console.log('[SW] Installing service worker...');

    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('[SW] Caching critical assets');
                // Use addAll with error handling for each asset
                return Promise.allSettled(
                    PRECACHE_ASSETS.map(url =>
                        cache.add(url).catch(err => {
                            console.warn(`[SW] Failed to cache ${url}:`, err.message);
                        })
                    )
                );
            })
            .then(() => {
                console.log('[SW] Precache complete');
                return self.skipWaiting();
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('[SW] Activating service worker...');

    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames
                        .filter((name) => name !== CACHE_NAME)
                        .map((name) => {
                            console.log('[SW] Deleting old cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => {
                console.log('[SW] Claiming clients');
                return self.clients.claim();
            })
    );
});

// Fetch event - use appropriate caching strategy per resource type
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Only cache same-origin requests
    if (url.origin !== location.origin) {
        return;
    }

    // HTML files: ALWAYS network-first (so code changes load immediately)
    if (url.pathname.endsWith('.html') || url.pathname === '/' || url.pathname.endsWith('/')) {
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    if (response.ok) {
                        const responseClone = response.clone();
                        caches.open(CACHE_NAME)
                            .then((cache) => cache.put(event.request, responseClone));
                    }
                    return response;
                })
                .catch(() => {
                    // Network failed - fall back to cache for offline support
                    return caches.match(event.request);
                })
        );
        return;
    }

    // Static assets (WASM, JS, images): cache-first with background revalidation
    if (shouldCache(url.pathname)) {
        event.respondWith(
            caches.match(event.request)
                .then((cachedResponse) => {
                    if (cachedResponse) {
                        // Return cached version, but update cache in background
                        updateCache(event.request);
                        return cachedResponse;
                    }

                    // Not in cache - fetch from network and cache it
                    return fetch(event.request)
                        .then((response) => {
                            if (response.ok) {
                                const responseClone = response.clone();
                                caches.open(CACHE_NAME)
                                    .then((cache) => cache.put(event.request, responseClone));
                            }
                            return response;
                        });
                })
        );
    }
});

// Determine if a request should be cached (static assets only)
function shouldCache(pathname) {
    // Cache WASM, JS, and image assets (NOT HTML - handled separately)
    return pathname.endsWith('.wasm') ||
           pathname.endsWith('.js') ||
           pathname.endsWith('.svg') ||
           pathname.endsWith('.png') ||
           pathname.includes('/crypto_core');
}

// Update cache in background (stale-while-revalidate)
function updateCache(request) {
    fetch(request)
        .then((response) => {
            if (response.ok) {
                caches.open(CACHE_NAME)
                    .then((cache) => cache.put(request, response));
            }
        })
        .catch(() => {
            // Network failed, that's okay - we already served from cache
        });
}

// Handle messages from main thread
self.addEventListener('message', (event) => {
    if (event.data === 'skipWaiting') {
        self.skipWaiting();
    }

    if (event.data === 'clearCache') {
        caches.delete(CACHE_NAME)
            .then(() => console.log('[SW] Cache cleared'));
    }
});
