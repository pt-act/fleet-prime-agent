#!/bin/bash
# Live smoke of the NEW request boundary (dev path), post-implementation.
set -u
WT="/Users/rna/Desktop/fleet prime agent/fleet-prime-agent/.worktrees/request-boundary-round1"
PORT=3111
LOG=/tmp/rb-smoke.log
export HOME=/tmp/rb-smoke-home; rm -rf "$HOME"; mkdir -p "$HOME"
cd "$WT/web/app" || exit 1
nohup env VITE_FLEET_DISABLE_AGENTATION=1 pnpm exec vite dev --port $PORT --strictPort --host 127.0.0.1 > "$LOG" 2>&1 &
VPID=$!
for i in $(seq 1 60); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break; sleep 1; done
B="http://127.0.0.1:$PORT"
echo "--- 1. bootstrap (no Origin, loopback Host) ---"
curl -s -o /tmp/s1.json -w "status=%{http_code}\n" --max-time 60 "$B/api/bootstrap"
GRANT=$(python3 -c "import json;print(json.load(open('/tmp/s1.json'))['grant'])" 2>/dev/null)
echo "grant obtained: $([ -n "$GRANT" ] && echo yes || echo NO)"
echo "--- 2. cross-port origin POST (F07 fixed?) ---"
curl -s -o /tmp/s2.json -w "status=%{http_code}\n" --max-time 60 -X POST "$B/api/chat/new" -H "Origin: http://127.0.0.1:9999" -H "Content-Type: application/json" -d '{}'
head -c 200 /tmp/s2.json; echo ""
echo "--- 3. non-loopback origin POST (dev gate) ---"
curl -s -o /tmp/s3.json -w "status=%{http_code}\n" --max-time 60 -X POST "$B/api/chat/new" -H "Origin: http://evil.example.com" -H "Content-Type: application/json" -d '{}'
head -c 200 /tmp/s3.json; echo ""
echo "--- 4. grant but NO protocol header on mutation ---"
curl -s -o /tmp/s4.json -w "status=%{http_code}\n" --max-time 60 -X POST "$B/api/chat/new" -H "Origin: $B" -H "Authorization: Bearer $GRANT" -H "Content-Type: application/json" -d '{}'
head -c 200 /tmp/s4.json; echo ""
echo "--- 5. grant + protocol: admitted ---"
curl -s -o /tmp/s5.json -w "status=%{http_code}\n" --max-time 60 -X POST "$B/api/chat/new" -H "Origin: $B" -H "Authorization: Bearer $GRANT" -H "X-Fleet-Protocol: 2" -H "Content-Type: application/json" -d '{}'
head -c 120 /tmp/s5.json; echo ""
echo "--- 6. no grant on read ---"
curl -s -o /tmp/s6.json -w "status=%{http_code}\n" --max-time 60 "$B/api/chat/sessions" -H "Origin: $B"
head -c 200 /tmp/s6.json; echo ""
echo "--- 7. grant on read: admitted ---"
curl -s -o /tmp/s7.json -w "status=%{http_code}\n" --max-time 60 "$B/api/chat/sessions" -H "Origin: $B" -H "Authorization: Bearer $GRANT"
head -c 80 /tmp/s7.json; echo ""
echo "--- 8. invalid sessionId (F26 fixed?) ---"
curl -s -o /tmp/s8.json -w "status=%{http_code}\n" --max-time 60 "$B/api/chat/session?sessionId=not-a-uuid&attachmentId=x" -H "Origin: $B" -H "Authorization: Bearer $GRANT"
head -c 300 /tmp/s8.json; echo ""
echo "--- 9. text/plain mutation (415?) ---"
curl -s -o /tmp/s9.json -w "status=%{http_code}\n" --max-time 60 -X POST "$B/api/chat/new" -H "Origin: $B" -H "Authorization: Bearer $GRANT" -H "X-Fleet-Protocol: 2" -H "Content-Type: text/plain" -d '{}'
head -c 200 /tmp/s9.json; echo ""
echo "--- 10. grant replay with wrong value (401?) ---"
curl -s -o /tmp/s10.json -w "status=%{http_code}\n" --max-time 60 "$B/api/chat/sessions" -H "Origin: $B" -H "Authorization: Bearer not-the-grant"
head -c 200 /tmp/s10.json; echo ""
kill $VPID 2>/dev/null; pkill -P $VPID 2>/dev/null
echo "smoke done"
