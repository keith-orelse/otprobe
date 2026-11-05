# Rules: schema, condition language, evaluation, scoring

Compliance, telemetry and event rules are **data** in [`/rules`](../rules). Each file is validated against
[`rules/schema.json`](../rules/schema.json) at startup and in CI. The rule engine contains no rule-specific code,
and the UI never hardcodes a status.

| File | Kind | Evaluated on |
|---|---|---|
| `linux_host_baseline.yaml` | compliance | deep assessment evidence from the Go agent's Linux collectors; agentless SSH data for LNX-FW-001 and LNX-OS-001 |
| `windows_engineering_baseline.yaml` | compliance | deep assessment evidence (agent); agentless probe data for rules with `AGENTLESS` in `sources` (WIN-FW-001, WIN-AV-001, WIN-OS-001) |
| `telemetry.yaml` | telemetry | every MQTT message on `topic`, plus a staleness timer (`stale_after_sec`) |
| `network.yaml` | event | discovery events (rogue device) |
| `classification.yaml` | classification signals | after each probe |
| `eligibility.yaml` | eligibility policy | after classification |

## 1. Rule fields

```yaml
- id: WIN-FW-001                     # ^[A-Z]{2,5}-[A-Z0-9]{2,8}-\d{3}$, unique within the policy
  title: Host firewall enabled
  severity: HIGH                     # CRITICAL | HIGH | MEDIUM | LOW — scoring weight + default finding severity
  sources: [DEEP_AGENT, AGENTLESS]   # which evidence stages may evaluate this rule
  applies_to: { os.family: "== 'windows'" }   # optional, in addition to policy.applies_to
  evidence: firewall.state           # path into the evidence document; `[]` projects over a list
  condition: "== 'enabled'"          # true → PASS
  expected: enabled on all profiles  # shown in findings
  on_fail:    { status: FAIL, severity: HIGH }   # FAIL or WARNING
  on_missing: { status: UNKNOWN }                # default
  remediation: …
  references: [IEC 62443-3-3 SR 5.2, NIST SP 800-82r3 6.2.1]
```

## 2. Condition language

The engine uses a small hand-written parser. It **never** calls `eval`. Conditions apply to the resolved evidence
value `v`.

```ebnf
condition   = disjunction ;
disjunction = conjunction { "or" conjunction } ;
conjunction = clause { "and" clause } ;
clause      = [ "count" ] cmp_op operand          (* count: v must be a list; compares len(v) *)
            | [ "not" ] "in" operand              (* v ∈ list *)
            | [ "not" ] "contains" operand        (* list: element ∈ v ; string: substring *)
            | [ "not" ] "intersects" operand      (* list v ∩ list operand ≠ ∅ *)
            | [ "not" ] "matches" string          (* Python `re.search`; on a list: any element matches;
                                                     "not matches": no element matches *)
            | "is" [ "not" ] "empty" ;
cmp_op      = "==" | "!=" | "<" | "<=" | ">" | ">=" ;
operand     = string | number | "true" | "false" | list | "$" identifier ;   (* $x → policy parameter *)
list        = "[" [ operand { "," operand } ] "]" ;
string      = "'" { char } "'" ;
```

`and` binds tighter than `or`, and there are no parentheses. Rules that need more structure are split into
several rules.

## 3. Evaluation order (per rule)

1. **Applicability.** If the policy's `applies_to` or the rule's `applies_to` is false, or the evaluating source
   is not in `sources`, the rule is *not evaluated*. It produces no result and does not count toward the score.
2. **Missing evidence first.** Resolve `evidence`. If the path is absent, `null`, or a projection over an absent
   list, the result is `on_missing` (default **UNKNOWN**). The rule records `message: "evidence 'usb.storage_policy'
   not present"`.
3. **Type check.** If the operator is incompatible with the value type (e.g. `>=` on a string), the result is
   **UNKNOWN** with `message: "type mismatch: …"` and a `RULE_EVALUATION_ERROR` audit event. A rule error never
   turns into a FAIL.
4. **Condition.** True → **PASS**. False → `on_fail.status` (`FAIL` or `WARNING`) with `on_fail.severity`.
5. Record `rule_results` with `observed` (the resolved value), `expected`, `evidence_path`, `rule_version`.

Statuses: `PASS`, `FAIL`, `WARNING`, `UNKNOWN`.

## 4. Evidence document (deep agent)

The agent uploads one normalised JSON document per run. Field paths match [PROVENANCE.md](PROVENANCE.md).

```json
{
  "schemaVersion": "1.0",
  "collectedAt": "2026-11-02T10:15:04Z",
  "collectors": {"os": "ok", "firewall": "ok", "usb": "error: registry key HKLM\\…\\USBSTOR unreadable"},
  "os": {"family": "windows", "name": "Microsoft Windows 11 Enterprise", "product": "Windows 11 Enterprise", "version": "24H2", "build": "26100.2314"},
  "firewall": {"state": "enabled", "profiles": {"domain": "on", "private": "on", "public": "on"}, "defaultInbound": "block", "ruleCount": 412},
  "antivirus": {"product": "Microsoft Defender Antivirus", "state": "running", "signature_age_days": 1, "realtime": true},
  "patches": {"installed": ["KB5044284", "KB5046617"], "missing": ["KB5048667", "KB5050009"], "missing_count": 2},
  "software": {"installed": [{"name": "RemoteTool Demo", "version": "3.2.0", "publisher": "Demo Corp"}]},
  "services": {"running": [{"name": "WinRM", "state": "running", "startType": "auto"}]},
  "local_admins": {"members": [{"name": "Administrator", "enabled": false}], "enabled_count": 3},
  "password_policy": {"min_length": 14, "complexity": true, "lockout_threshold": 5, "max_age_days": 90},
  "audit": {"logon_events": "success_and_failure"},
  "network": {"interfaces": [{"name": "Ethernet0", "ip": "192.168.20.13", "mac": "00:1A:2B:3C:20:13"}], "listening": [135, 445, 3389, 5986]},
  "agent": {"health": "healthy", "version": "1.1.0", "uptime_sec": 3600}
}
```

`usb` is **absent**, not `null`, because its collector failed. `WIN-USB-001` therefore evaluates to UNKNOWN.

## 5. Compliance score

```
weight(sev)  = CRITICAL 10 · HIGH 6 · MEDIUM 3 · LOW 1        (rule.severity)
credit(stat) = PASS 1.0 · WARNING 0.5 · FAIL 0.0
evaluated    = results where status ∈ {PASS, WARNING, FAIL}    (UNKNOWN excluded)

score = round( 100 × Σ_evaluated weight·credit / Σ_evaluated weight )      (null if evaluated is empty)
```

The UI always shows the UNKNOWN count next to the score (for example **74 %** · 1 unknown), so a score cannot
look better than it is just because evidence was missing.

**Worked example (eng-ws-01, first deep assessment; acceptance E):**

| Rule | Sev | w | Status | w·credit |
|---|---|---|---|---|
| WIN-FW-001 | HIGH | 6 | PASS | 6 |
| WIN-AV-001 | CRITICAL | 10 | PASS | 10 |
| WIN-PATCH-001 | HIGH | 6 | FAIL | 0 |
| WIN-SW-001 | MEDIUM | 3 | WARNING | 1.5 |
| WIN-OS-001 | HIGH | 6 | PASS | 6 |
| WIN-PWD-001 | MEDIUM | 3 | PASS | 3 |
| WIN-PWD-002 | LOW | 1 | PASS | 1 |
| WIN-ADM-001 | MEDIUM | 3 | FAIL | 0 |
| WIN-USB-001 | MEDIUM | 3 | UNKNOWN | — |
| WIN-AUD-001 | LOW | 1 | PASS | 1 |
| AGT-HEALTH-001 | MEDIUM | 3 | PASS | 3 |
| **Total** | | **42** | | **31.5** → **75 %**, 1 UNKNOWN |

Findings created: WIN-PATCH-001 (HIGH), WIN-SW-001 (MEDIUM, WARNING), WIN-ADM-001 (MEDIUM).

## 6. Findings and drift

- Each FAIL/WARNING result upserts the finding (asset_id, rule_id). Lifecycle:
  [STATE_MACHINES.md §5](STATE_MACHINES.md#5-finding). `source` comes from the evaluating stage.
- **Drift:** after evaluation, each result is compared with the same rule's result in `previous_run_id`. The
  previous run is the asset's last `EVALUATED` run of the same policy **and the same source** (deep agent or
  agentless), so partial agentless evidence never produces false drift against a deep run. A PASS → FAIL or
  PASS → WARNING change creates a `drift_events` row linked to the finding, an audit event
  `CONFIGURATION_DRIFT_DETECTED` and an SSE `drift.detected` event.
- **Configuration changes:** the evidence documents of the two runs are diffed path by path into
  `evidence_changes`. This feeds "configuration changes" on the dashboard even when no rule status changes
  (for example, a patch removed while WIN-PATCH-001 was already failing).
