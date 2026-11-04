#!/usr/bin/env bash
# Walk acceptance criteria E and F through the REAL API with curl.
# Needs a running API + agent runtime. Deploys an agent on eng-ws-01 first if it has none.
#   API=http://127.0.0.1:8000 ./scripts/try_e_f.sh
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
wait_for() { for _ in $(seq 1 $(( ${4:-60} * 2 ))); do
    [ "$(get "$1" "$2" | j "$3")" = "True" ] && return 0; sleep 0.5; done
  echo "timeout waiting for $2 :: $3" >&2; exit 1; }
step() { printf '\n\033[1;33m== %s\033[0m\n' "$*"; }
results() { get "$OP" "/assessments/$1" | j '"  score {}%  counts {}\n".format(d["score"], d["counts"]) + "\n".join("  {:15} {:8} prev={:8} observed={}".format(r["ruleId"], r["status"], str(r["previousStatus"]), r["observed"]) for r in d["results"])'; }
assess() {  # prints run id
  local run; run=$(post "$OP" "/assets/$ASSET/assessments" | j 'd["id"]')
  wait_for "$OP" "/assessments/$run" 'd["status"] in ("EVALUATED","TIMED_OUT","FAILED")' 60; echo "$run"; }
firewall() { post "$AD" /demo/devices/dev-ews01/config "{\"control\":\"firewall\",\"value\":\"$1\"}" | j '"  admin set firewall -> "+d["config"]["firewall"]'; }
fwfinding() { get "$OP" "/findings?ruleId=WIN-FW-001&assetId=$ASSET" | j '"  GET /findings?ruleId=WIN-FW-001 -> " + (", ".join("{} {} reopenCount={} observed={}".format(f["status"], f["severity"], f["reopenCount"], f["observed"]) for f in d["items"]) or "none")'; }

OP=$(login operator); AP=$(login approver); AD=$(login admin)

if ! get "$OP" "/assets?q=192.168.20.13" | j 'd["total"] > 0' | grep -q True; then
  step "Setup: discover 192.168.20.0/24"
  JOB=$(post "$OP" /discovery/jobs '{"targets":["192.168.20.0/24"]}' | j 'd["id"]')
  wait_for "$OP" "/discovery/jobs/$JOB" 'd["status"]=="COMPLETED"'
fi
ASSET=$(get "$OP" "/assets?q=192.168.20.13" | j 'd["items"][0]["id"]')
if [ "$(get "$OP" "/assets/$ASSET" | j 'd["agentState"]')" != "ONLINE" ]; then
  step "Setup: probe eng-ws-01 and deploy an agent (request -> approve -> precheck -> deploy)"
  P=$(post "$OP" "/assets/$ASSET/probes" | j 'd["id"]'); wait_for "$OP" "/probes/$P" 'd["status"] in ("COMPLETED","PARTIAL")'
  DEP=$(post "$OP" /deployments "{\"assetId\":\"$ASSET\",\"packageId\":\"pkg-probe-agent-1.1.0\",\"purpose\":\"Deep compliance monitoring\"}")
  post "$AP" "/approvals/$(echo "$DEP" | j 'd["approval"]["id"]')/approve" >/dev/null
  DEP_ID=$(echo "$DEP" | j 'd["id"]')
  post "$OP" "/deployments/$DEP_ID/precheck" >/dev/null; wait_for "$OP" "/deployments/$DEP_ID" 'd["status"]=="PRECHECK_PASSED"'
  post "$OP" "/deployments/$DEP_ID/deploy" >/dev/null; wait_for "$OP" "/deployments/$DEP_ID" 'd["status"]=="COMPLETED"' 90
  wait_for "$OP" "/assets/$ASSET" 'd["agentState"]=="ONLINE"'
  echo "  agent ONLINE"
fi
firewall enabled >/dev/null

step "E. First deep assessment on eng-ws-01 (agent collects, server evaluates rules/ data)"
RUN1=$(assess); results "$RUN1"
get "$OP" "/findings?assetId=$ASSET&status=OPEN,REOPENED" | j '"  open findings:\n" + "\n".join("    {} {:8} {:15} {}".format(f["severity"], f["resultStatus"], f["ruleId"], f["observed"]) for f in d["items"])'

step "F1. Admin disables the firewall, operator reassesses -> PASS->FAIL, drift, OPEN HIGH finding"
firewall disabled; RUN2=$(assess); results "$RUN2" | grep -E "score|WIN-FW-001"
get "$OP" "/assessments/$RUN2" | j '"  drift: " + str([(x["ruleId"], x["fromStatus"], x["toStatus"], x["before"], x["after"]) for x in d["driftEvents"]])'
fwfinding
get "$OP" "/audit-events?action=CONFIGURATION_DRIFT_DETECTED" | j '"  audit: {} CONFIGURATION_DRIFT_DETECTED event(s), latest {}".format(d["total"], d["items"][0]["details"])'

step "F2. Re-enable and reassess -> finding RESOLVED"
firewall enabled; RUN3=$(assess); results "$RUN3" | grep -E "WIN-FW-001"; fwfinding

step "F3. Regression: disable again and reassess -> finding REOPENED"
firewall disabled; RUN4=$(assess); results "$RUN4" | grep -E "WIN-FW-001"; fwfinding

step "Finding lifecycle"
FID=$(get "$OP" "/findings?ruleId=WIN-FW-001&assetId=$ASSET" | j 'd["items"][0]["id"]')
get "$OP" "/findings/$FID" | j '"\n".join("  {} -> {:9} by {} {}".format(e["fromStatus"], e["toStatus"], e["actor"], e["reason"] or "") for e in d["events"])'
firewall enabled >/dev/null
echo; echo "(firewall restored to enabled; the next assessment will resolve the finding again)"
