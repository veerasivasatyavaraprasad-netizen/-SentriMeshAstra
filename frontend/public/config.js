// Placeholder for local dev (`npm run dev` / `vite preview`) — the real
// version of this file is generated at container startup by
// docker-entrypoint.sh from the actual deployment environment. Leaving
// window.__ENV__ unset here is deliberate: it makes getApiBaseUrl() fall
// through to Vite's own build-time VITE_API_BASE_URL / the localhost
// default, which is exactly what local development wants.
window.__ENV__ = {};
