#!/usr/bin/env bash
# Exercises the hive Worker. Run `wrangler dev` in worker/ first (with HIVE_SECRET in .dev.vars).
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8787}"
SECRET="${HIVE_SECRET:?set HIVE_SECRET to the same value as worker/.dev.vars}"
ORIGIN="${ORIGIN:-https://xivlabs.tech}"
BODY=/tmp/hive_test_body
pass=0
fail=0

check() {
  if [ "$2" = "$3" ]; then echo "PASS: $1"; pass=$((pass + 1));
  else echo "FAIL: $1 (expected $2, got $3)"; echo "  body: $(head -c 300 $BODY)"; fail=$((fail + 1)); fi
}

# batch <sent_at offset secs> <events json> [stats json] -> prints JSON body
batch() {
  python3 -c "
import json,sys,time
b={'sent_at': time.time()+float(sys.argv[1]), 'events': json.loads(sys.argv[2])}
if len(sys.argv) > 3: b['stats'] = json.loads(sys.argv[3])
print(json.dumps(b))" "$@"
}

# A snapshot as the sensor sends it, plus junk the Worker must trim: 15 paths, a 1000-char key,
# control characters and an impossible map point.
STATS=$(python3 -c "
import json
top=lambda k,n: {'k':k,'n':n}
print(json.dumps({'generated_at':0,'total_24h':3,'total_7d':4,'unique_sources_24h':3,
 'by_service_24h':[top('ssh',2),top('http',1)],
 'top_usernames':[top('root',2)], 'top_passwords':[top('123456',2)],
 'top_paths':[top('/.env',5), top('A'*1000,4)] + [top(f'/p{i}',1) for i in range(13)],
 'top_countries':[top('NL',2)], 'top_user_agents':[top('zgrab\\u001b[31m/0.x',1)],
 'points_24h':[{'lat':52.4,'lon':4.9,'n':2},{'lat':999,'lon':0,'n':1}]}))")
sign() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1; }
ingest() {  # ingest <body> [signature]
  local sig="${2:-$(sign "$1")}"
  curl -s -o $BODY -w "%{http_code}" -X POST "$BASE_URL/ingest" -H "X-Hive-Signature: $sig" --data-binary "$1"
}

NOW=$(date +%s)
XSS='<img src=x onerror=alert(1)>'
EVENTS=$(python3 -c "
import json,sys
now=int(sys.argv[1]); xss=sys.argv[2]
print(json.dumps([
 {'ts':now-5,'service':'ssh','ip':'203.0.113.57','country':'NL','city':'Amsterdam','lat':52.37,'lon':4.89,'username':'root','password':'123456'},
 {'ts':now-4,'service':'ssh','ip':'2001:db8:1:2::5','country':'US','lat':37.75,'lon':-97.82,'username':xss,'password':'admin'},
 {'ts':now-3,'service':'http','ip':'198.51.100.9','country':'CN','lat':34.77,'lon':113.72,'method':'GET','path':'/.env','ua':'zgrab/0.x'},
 {'ts':now-2,'service':'telnet','ip':'198.51.100.10'},
 {'ts':now-999999,'service':'ssh','ip':'198.51.100.11','username':'old'}
]))" "$NOW" "$XSS")

echo "== Testing hive Worker at $BASE_URL =="

GOOD=$(batch 0 "$EVENTS" "$STATS")
check "no signature is rejected" 401 "$(curl -s -o $BODY -w '%{http_code}' -X POST "$BASE_URL/ingest" --data-binary "$GOOD")"
check "wrong signature is rejected" 401 "$(ingest "$GOOD" "$(printf 'x' | openssl dgst -sha256 -hmac wrong -r | cut -d' ' -f1)")"
check "stale batch is rejected" 401 "$(ingest "$(batch -600 "$EVENTS")")"
check "future batch is rejected" 401 "$(ingest "$(batch 600 "$EVENTS")")"
check "signed invalid JSON returns 400" 400 "$(ingest 'not json')"
BIG=$(python3 -c "import json,time; print(json.dumps({'sent_at':time.time(),'events':[{'ts':time.time(),'service':'ssh','ip':'1.2.3.4'}]*51}))")
check "oversized batch is rejected" 413 "$(ingest "$BIG")"

check "valid batch is accepted" 200 "$(ingest "$GOOD")"
check "only ssh/http events within 24h are stored" '{"accepted":3,"stats":true}' "$(cat $BODY)"

sleep 31  # let the 30s edge cache expire so reads see the new rows
check "GET /recent returns 200" 200 "$(curl -s -o $BODY -w '%{http_code}' -H "Origin: $ORIGIN" "$BASE_URL/recent?limit=10")"
python3 - "$BODY" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1]))
ips=[r['ip_masked'] for r in rows]
assert '203.0.113.x' in ips and '2001:db8:1::x' in ips, ips
assert not any(ip.split('.')[-1].isdigit() and ip.count('.')==3 for ip in ips), ips
assert not any(k=='ip' for r in rows for k in r), 'raw ip field leaked'
print("PASS: /recent only exposes masked IPs")
PY
[ $? -eq 0 ] && pass=$((pass + 1)) || fail=$((fail + 1))

check "allowed origin gets CORS header" "access-control-allow-origin: $ORIGIN" \
  "$(curl -s -D - -o /dev/null -H "Origin: $ORIGIN" "$BASE_URL/stats" | tr -d '\r' | grep -i '^access-control-allow-origin' | tr 'A-Z' 'a-z' | sed "s#$(echo $ORIGIN | tr 'A-Z' 'a-z')#$ORIGIN#")"
check "other origin gets no CORS header" "" \
  "$(curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$BASE_URL/stats" | tr -d '\r' | grep -i '^access-control-allow-origin')"

curl -s -o $BODY "$BASE_URL/stats"
python3 - "$BODY" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
assert s['total_24h']==3 and s['total_7d']==4, s
paths=[t['k'] for t in s['top_paths']]
assert paths[0]=='/.env' and len(paths)==10, paths
assert len(paths[1])==256, len(paths[1])
assert '\x1b' not in s['top_user_agents'][0]['k'], s['top_user_agents']
assert s['points_24h']==[{'lat':52.4,'lon':4.9,'n':2}], s['points_24h']
print("PASS: /stats serves the sanitized snapshot")
PY
[ $? -eq 0 ] && pass=$((pass + 1)) || fail=$((fail + 1))

# 12 more batches of 50 events: the feed table must stay capped at 500 rows.
for i in $(seq 1 12); do
  FILL=$(python3 -c "import json,time; print(json.dumps([{'ts':time.time(),'service':'http','ip':'192.0.2.1','method':'GET','path':f'/fill{i}'} for i in range(50)]))")
  ingest "$(batch 0 "$FILL")" >/dev/null
done
if [ -n "${LOCAL_DB_DIR:-}" ]; then
  rows=$(cd "$LOCAL_DB_DIR" && wrangler d1 execute hive-db --local --json --command "SELECT COUNT(*) AS n FROM events" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['results'][0]['n'])")
  check "feed table is pruned to 500 rows" 500 "$rows"
fi

check "GET /nope is 404" 404 "$(curl -s -o $BODY -w '%{http_code}' "$BASE_URL/nope")"

echo; echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
