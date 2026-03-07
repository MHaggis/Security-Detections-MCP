FROM node:20-slim

# Install git and other dependencies
RUN apt-get update && apt-get install -y \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone the repo
RUN git clone --depth 1 https://github.com/MHaggis/Security-Detections-MCP.git .

# Install dependencies and build
RUN npm install && npm run build

# Create detections directory
RUN mkdir -p /detections

# Create cache directory for SQLite DB
RUN mkdir -p /root/.cache/security-detections-mcp

# Optional: Download detection rule repos at build time (comment out to skip)
# Uncomment to bake rules into the image (~large image, but ready to go)
# RUN mkdir -p /detections && cd /detections && \
#     git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git && \
#     cd sigma && git sparse-checkout set rules rules-threat-hunting && cd .. && \
#     git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git && \
#     cd security_content && git sparse-checkout set detections stories && cd .. && \
#     git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git && \
#     cd detection-rules && git sparse-checkout set rules && cd ..

# Environment variables — override these at runtime with -e or --env-file
ENV SIGMA_PATHS=/detections/sigma/rules,/detections/sigma/rules-threat-hunting
ENV SPLUNK_PATHS=/detections/security_content/detections
ENV ELASTIC_PATHS=/detections/detection-rules/rules
ENV STORY_PATHS=/detections/security_content/stories

# MCP server communicates over stdio — no port needed
CMD ["node", "dist/index.js"]
