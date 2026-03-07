#!/usr/bin/env bash
# setup.sh — Download detection repos and start the MCP container
set -e

echo "==> Creating detections directory..."
mkdir -p detections && cd detections

echo "==> Downloading Sigma rules (~3000+ rules)..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..

echo "==> Downloading Splunk ESCU detections + stories..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections stories && cd ..

echo "==> Downloading Elastic detection rules..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules && cd ..

cd ..

echo ""
echo "==> Detection repos ready. Building and starting the container..."
docker compose up --build -d

echo ""
echo "Done! Container is running."
echo ""
echo "To use as a stdio MCP server (e.g. with Claude Desktop or Cursor):"
echo "  docker exec -i security-detections-mcp node dist/index.js"
echo ""
echo "To view logs:"
echo "  docker compose logs -f"
echo ""
echo "To stop:"
echo "  docker compose down"
