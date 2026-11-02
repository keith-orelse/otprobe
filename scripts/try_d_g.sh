#!/usr/bin/env bash
# Walk acceptance criteria D and G through the REAL API with curl.
# Needs: a running API and a running agent runtime (separate process). Python 3 is used only to read JSON.
#   API=http://127.0.0.1:8000 ./scripts/try_d_g.sh
set -euo pipefail
API=${API:-http://127.0.0.1:8000}
V1="$API/api/v1"
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }
key() { python3 -c "import uuid; print(uuid.uuid4())"; }
login() { curl -sf "$V1/auth/login" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$1-demo\"}" | j 'd["accessToken"]'; }
get() { curl -sf "$V1$2" -H "Authorization: Bearer $1"; }
post() {
  local body=${3:-}; [ -n "$body" ] || body='{}'
  curl -s "$V1$2" -H "Authorization: Bearer $1" -H "Idempotency-Key: $(key)" -H 'Content-Type: application/json' -d "$body"
}
wait_for() { # token path python-expr timeout
  for _ in $(seq 1 $(( ${4:-60} * 2 ))); do
    if [ "$(get "$1" "$2" | j "$3")" = "True" ]; then return 0; fi; sleep 0.5
  done; echo "timeout waiting for $2 :: $3" >&2; exit 1
}
step() { printf '\n\033[1;33m== %s\033[0m\n' "$*"; }

OP=$(login operator); AP=$(login approver); AD=$(login admin)

step "Discover 192.168.20.0/24 and probe eng-ws-01 (operator)"
JOB=$(post "$OP" /discovery/jobs '{"targets":["192.168.20.0/24"]}' | j 'd["id"]')
wait_for "$OP" "/discovery/jobs/$JOB" 'd["status"]=="COMPLETED"'
ASSET=$(get "$OP" "/assets?q=192.168.20.13" | j 'd["items"][0]["id"]')
PROBE=$(post "$OP" "/assets/$ASSET/probes" | j 'd["id"]')
wait_for "$OP" "/probes/$PROBE" 'd["status"] in ("COMPLETED","PARTIAL")'
get "$OP" "/assets/$ASSET" | j '"eligibility: "+d["eligibility"]+" | deployAgent: "+str(d["deployAgent"])'

step "D1. Operator requests deployment -> PENDING_APPROVAL"
DEP=$(post "$OP" /deployments "{\"assetId\":\"$ASSET\",\"packageId\":\"pkg-probe-agent-1.1.0\",\"purpose\":\"Deep compliance monitoring\"}")
DEP_ID=$(echo "$DEP" | j 'd["id"]'); APPR=$(echo "$DEP" | j 'd["approval"]["id"]')
echo "$DEP" | j '"status: "+d["status"]+" | deploy action: "+d["actions"]["deploy"]["reason"]'

step "D2. Requester cannot approve own request"
echo "operator approves own request  -> $(post "$OP" "/approvals/$APPR/approve" | j 'str(d["status"])+" "+d["title"]')"
DEP2=$(get "$AD" "/assets?q=192.168.20.14" | j 'd["items"][0]["id"]')
P2=$(post "$AD" "/assets/$DEP2/probes" | j 'd["id"]'); wait_for "$AD" "/probes/$P2" 'd["status"]!="RUNNING" and d["status"]!="QUEUED"'
A2=$(post "$AD" /deployments "{\"assetId\":\"$DEP2\",\"packageId\":\"pkg-probe-agent-1.1.0\",\"purpose\":\"Admin request\"}" | j 'd["approval"]["id"]')
echo "admin approves own request     -> $(post "$AD" "/approvals/$A2/approve" | j 'str(d["status"])+" "+d["type"].rsplit("/",1)[1]')"

step "D3. Approver approves the operator's request"
post "$AP" "/approvals/$APPR/approve" | j '"approval "+d["status"]+" by "+d["decidedBy"]'

step "D4. Precheck (operator = requester)"
post "$OP" "/deployments/$DEP_ID/precheck" >/dev/null
wait_for "$OP" "/deployments/$DEP_ID" 'd["status"] in ("PRECHECK_PASSED","PRECHECK_FAILED")'
get "$OP" "/deployments/$DEP_ID" | j '"\n".join("  {:20} {:4} {}".format(c["check"], c["status"], c["detail"]) for c in d["precheck"])'

step "D5. Deploy -> agent installs, enrolls itself (outbound) and heartbeats"
post "$OP" "/deployments/$DEP_ID/deploy" >/dev/null
wait_for "$OP" "/deployments/$DEP_ID" 'd["status"] in ("COMPLETED","FAILED")' 90
get "$OP" "/deployments/$DEP_ID" | j '"\n".join("  {:20} {:7} {}".format(s["name"], s["status"], s["detail"]) for s in d["steps"])+"\n  => "+d["status"]'
AGENT=$(get "$OP" "/deployments/$DEP_ID" | j 'd["agentId"]')
sleep 3
get "$OP" "/agents/$AGENT" | j '"agent "+d["id"][:8]+" "+d["status"]+", last heartbeat "+str(d["secondsSinceHeartbeat"])+" s ago"'
get "$OP" "/agents/$AGENT/heartbeats?limit=3" | j '"heartbeats received: "+str(d["total"])'

step "G1. Admin breaks the heartbeat (simulation control) -> STALE -> OFFLINE"
post "$AD" /demo/devices/dev-ews01/faults '{"fault":"heartbeat_blocked","enabled":true}' | j '"faults on dev-ews01: "+str(d["faults"])'
wait_for "$OP" "/agents/$AGENT" 'd["status"]=="STALE"' 90
get "$OP" "/agents/$AGENT" | j '"  "+d["status"]+" missed="+str(d["missedHeartbeats"])'
wait_for "$OP" "/agents/$AGENT" 'd["status"]=="OFFLINE"' 120
get "$OP" "/agents/$AGENT" | j '"  "+d["status"]+" missed="+str(d["missedHeartbeats"])+" last heartbeat "+str(d["secondsSinceHeartbeat"])+" s ago"'

step "G2. Restore heartbeat -> ONLINE"
post "$AD" /demo/devices/dev-ews01/faults '{"fault":"heartbeat_blocked","enabled":false}' >/dev/null
wait_for "$OP" "/agents/$AGENT" 'd["status"]=="ONLINE"' 60
get "$OP" "/agents/$AGENT" | j '"  "+d["status"]+" missed="+str(d["missedHeartbeats"])'

step "Audit trail for the agent (who did what)"
get "$OP" "/audit-events?entityId=$AGENT&limit=20" | j '"\n".join("  #{:<4} {:24} by {}".format(e["seq"], e["action"], e["actorName"]) for e in reversed(d["items"]))'
