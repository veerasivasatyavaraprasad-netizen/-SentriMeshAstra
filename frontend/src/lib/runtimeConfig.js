// Resolves the backend API base URL without requiring it to be baked in
// at Docker build time. Deployment platforms (Render, Railway, etc.)
// don't all forward blueprint env vars into a Docker build's ARGs the
// same way, and getting that wrong silently ships a build pointing at
// "http://localhost:8000" in production. Reading it at container
// *runtime* instead sidesteps that entirely: index.html loads
// /config.js (written by docker-entrypoint.sh from the real environment
// right before nginx starts), which sets window.__ENV__ before this
// bundle ever runs.
export function getApiBaseUrl() {
  if (typeof window !== "undefined" && window.__ENV__?.VITE_API_BASE_URL) {
    return window.__ENV__.VITE_API_BASE_URL;
  }
  // Vite's own build-time env — still works for `npm run dev` and any
  // build where a real value was actually passed as a build arg.
  return import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
}
