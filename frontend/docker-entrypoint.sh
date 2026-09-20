#!/bin/sh
# Writes the real backend URL into a static config.js from the actual
# container environment at startup — not baked in at Docker build time,
# which would depend on the deploy platform correctly forwarding a
# blueprint env var into `docker build --build-arg`, a mechanism this
# project doesn't rely on being right on the first try.
set -e

cat > /usr/share/nginx/html/config.js <<EOF
window.__ENV__ = { VITE_API_BASE_URL: "${VITE_API_BASE_URL:-}" };
EOF

exec "$@"
