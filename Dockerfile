# Antigravity CLI hub (agy --hub) on Render.
# One small Go binary serving its own web UI on 127.0.0.1:4400,
# fronted by a tiny Basic-auth gate proxy on $PORT (Render's public port).
FROM node:22-slim

# Tools the agy installer needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install Google's Antigravity CLI (official installer -> ~/.local/bin/agy).
RUN curl -fsSL https://antigravity.google/cli/install.sh | bash

WORKDIR /app
COPY proxy.mjs start.sh statetool.mjs ./
COPY skills ./skills
RUN chmod +x start.sh

# Render sets $PORT at runtime; start.sh is the single entrypoint:
# seed sign-in (if provided) -> attach MCP bridge -> start hub -> start gate.
CMD ["bash", "start.sh"]
