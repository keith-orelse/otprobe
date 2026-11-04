# Bundled MQTT broker

OTProbe ships its own broker (decision R5): **Eclipse Mosquitto 2.0.x**, pinned to an exact image version and
started by the same `docker compose`. Plant devices publish telemetry to it. OTProbe **subscribes only**, and
turns readings into telemetry findings with the existing rules.

## 1. Defaults

| Setting | Default | Why |
|---|---|---|
| Listener | `8883`, TLS 1.2+, on the host's plant-facing interface | Encrypted by default |
| Plain `1883` | **off** | Can be enabled by an admin for devices that cannot do TLS. Bound to listed subnets only, and raises finding `MQTT-BRK-002` while on |
| Anonymous access | **off** (`allow_anonymous false`) | |
| Authentication | Username + password (PBKDF2-SHA512), or client certificate per account | Certificates are recommended for gateways that support them |
| Authorisation | Mosquitto **dynamic security plugin** (roles and ACLs) | OTProbe manages accounts live, without restarting the broker |
| Certificates | Server certificate issued by the OTProbe CA (the same CA the agents pin) | One CA for the site. The CA certificate is downloadable from the console for device setup |
| Limits | `max_packet_size 256 KiB`, `max_connections 1000`, `max_inflight_messages 20` | Protects the broker from a misbehaving publisher |
| Persistence | Retained messages and the dynsec config on a volume | Survives restarts |
| Logs | stdout → `docker logs`; connection refusals are counted on the dashboard | |

## 2. Accounts and roles

Admins manage accounts in **Settings → MQTT** (`/api/v1/mqtt/accounts`). OTProbe applies them to Mosquitto
through the dynsec control topic (`$CONTROL/dynamic-security/v1`).

| Role | Can publish | Can subscribe | Created by |
|---|---|---|---|
| `otprobe-reader` | nothing | configured topic roots (default `plant/#`), plus `$SYS/#` | Seeded. Used by the OTProbe `api` |
| `otprobe-broker-admin` | `$CONTROL/dynamic-security/#` only | its response topic | Seeded. Used by the `api` **only** to manage accounts. Password in the vault |
| `publisher` | its own prefix only, e.g. `plant/line1/sensor01/#` | nothing | Admin, one per device or gateway |
| `gateway` | a prefix with sub-levels, e.g. `plant/line1/#` | nothing | Admin, for edge gateways that publish for many devices |

- **Passwords are shown once.** The API returns a new account's password a single time; after that it is stored
  only in the broker (hashed) and masked in OTProbe.
- Every account change is audited: `MQTT_ACCOUNT_CREATED`, `…_DISABLED`, `…_PASSWORD_ROTATED`.
- An account's ACL can never be `#` for publish. The API refuses it (`422 mqtt-acl-too-broad`).

## 3. Topic → asset mapping

Telemetry sources (`/api/v1/telemetry/sources`) tie topics to assets and metrics:

| Field | Example |
|---|---|
| `topicFilter` | `plant/line1/sensor01/temperature` or `plant/line1/+/temperature` |
| `assetId` | `ast_…` (or `fromTopicLevel: 2` to match the level against the asset name) |
| `metric` | `temperature` |
| `unit` | `C` |
| `payloadFormat` | `PLAIN` (a number) · `JSON_PATH` (`$.value`) · `SPARKPLUG_B` (L5 stretch goal) |

- **Unmapped topics** are not dropped. The console lists them (topic, last payload, message rate, publishing
  account) so an operator can map them with one click.
- Messages are validated (size, number parse) before rules run. Bad payloads are counted, not stored.
- Retention: raw messages for 7 days (configurable), then hourly min/avg/max per source.

## 4. Telemetry rules

`rules/telemetry.yaml` keeps its format. Rules can refer to a **metric** on a class of asset instead of a fixed
topic, so the same rule works across a site:

```yaml
- id: TEL-TEMP-002
  title: Sensor temperature critical
  applies_to: { metric: "== 'temperature'", asset.class: "== 'SENSOR'" }
  condition: "<= 95"
  on_fail: { status: FAIL, severity: CRITICAL }
- id: TEL-STALE-001
  title: Telemetry source silent
  applies_to: { metric: "exists" }
  stale_after_sec: 30
  on_stale: { status: FAIL, severity: HIGH }
```

Findings, drift and the staleness timer work as in the POC.

## 5. Broker security checks

**Our own broker** is checked at start-up and every hour. Problems become findings on the OTProbe server asset:

| Rule | Check | Severity |
|---|---|---|
| `MQTT-BRK-001` | Anonymous access is disabled | CRITICAL |
| `MQTT-BRK-002` | No plaintext listener is enabled | MEDIUM |
| `MQTT-BRK-003` | No account can publish to `#` or to `$CONTROL/#` (except the broker admin) | HIGH |
| `MQTT-BRK-004` | Server certificate valid for > 30 days | MEDIUM |
| `MQTT-BRK-005` | No enabled account unused for > 90 days | LOW |

**Other brokers found in scope** (port 1883 or 8883 open during discovery) can be checked by the optional
`mqtt_anon` plugin. It is off by default and enabled per scope entry. It sends one `CONNECT` with no credentials,
reads the `CONNACK` code and disconnects at once. It never subscribes or publishes.

| Rule | Check | Severity |
|---|---|---|
| `NET-MQTT-001` | Broker accepts anonymous connections | HIGH |
| `NET-MQTT-002` | Broker exposes plaintext MQTT (1883) | MEDIUM |

## 6. Network placement

- The broker listens on the OTProbe host. Plant firewalls must allow `8883/tcp` from publishing devices to the
  OTProbe host, and nothing else inbound except `443` (console + agents).
- OTProbe never connects **out** to devices over MQTT. Devices always connect in.
- For sites that already have a plant broker, a bridge configuration (plant broker → OTProbe broker, read-only
  topics) is documented as an option. It is not a default.

## 7. Testing

| Test | How |
|---|---|
| Anonymous refused, TLS-only, ACL limits | Container test: real Mosquitto + `mosquitto_pub`/`sub` with good and bad credentials |
| Accounts via dynsec | API creates an account → publish works on its prefix, fails outside it |
| Topic mapping, rules, staleness | Container test: publish values over 80 / 95 °C, stop publishing → findings open and resolve |
| Broker checks | Turn on the plaintext listener → `MQTT-BRK-002` opens. Turn it off → resolved |
| Lab | Real devices or OpenPLC publish through a gateway account; a sensor is unplugged → `TEL-STALE-001` |
