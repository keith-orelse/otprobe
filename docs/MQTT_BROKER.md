# Bundled MQTT broker (Mode A)

OTProbe runs its own broker, **Eclipse Mosquitto 2.x**, for sites that have none. Plant devices publish telemetry to
it, and OTProbe **only reads**. Readings become telemetry findings through `rules/telemetry.yaml`. Connecting
read-only to a plant's existing broker (Mode B) is not built yet.

```
OTProbe machine
├── OTProbe API ── otprobe-reader (subscribe only, 127.0.0.1) ──┐
└── Mosquitto (child process of OTProbe) ◀──────────────────────┘
          ▲  port 8883, TLS, one account per device
PLCs / sensors / gateways (publish only, each under its own topic prefix)
```

## 1. How it runs

`MQTT_BROKER=bundled` makes OTProbe start Mosquitto as a **child process** (decision L6-10). OTProbe:

- writes the broker's files into `MQTT_DIR` (default: `mqtt/` next to the database), owner-only (`0600`);
- starts it and waits until it reports "running";
- restarts it if it exits (after 2, 5, 10, then every 30 s);
- reloads it (`SIGHUP`) when an account changes;
- stops it when OTProbe stops.

Every file is rewritten from OTProbe's database at start-up, so the database is the only source of truth.

| File | Contents |
|---|---|
| `mosquitto.conf` | Listeners and limits (§2) |
| `passwd` | Accounts as Mosquitto PBKDF2-SHA512 hashes (`$7$…`, the `mosquitto_passwd` format) |
| `acl` | What each account may read and write (§3) |
| `server.pem`, `server.key`, `ca.pem` | Copies of OTProbe's server certificate, its key and the CA |
| `data/` | Retained messages |

Mosquitto must be installed on the machine (`brew install mosquitto` on a Mac, `apt install mosquitto` on
Debian/Ubuntu; it is included in the Docker image). If it is missing, OTProbe still starts and Settings → MQTT broker
says so.

## 2. Defaults

| Setting | Default | Why |
|---|---|---|
| Device listener | `MQTT_PORT=8883`, TLS, every interface (`MQTT_BIND` to restrict it) | Encrypted by default |
| Certificate | OTProbe's server certificate: `otprobe-server.pem/.key` next to `OTPROBE_TLS_CA_FILE` (or `MQTT_TLS_CERT_FILE` / `MQTT_TLS_KEY_FILE`) | One CA for the site, the same one the agents pin. Devices download it from Settings → MQTT broker → Download CA certificate (`GET /api/v1/mqtt/ca.pem`) |
| Plain MQTT | `MQTT_PLAIN_PORT=0`, **off** | For devices that cannot do TLS. Check MQTT-BRK-002 fails while it is on |
| OTProbe's own listener | 127.0.0.1 only, a random port each start | Only OTProbe's reader uses it. It still needs a password |
| Anonymous access | **off** (`allow_anonymous false`) | Checked live at every start (MQTT-BRK-001) |
| Limits | 256 KiB per message, 1000 connections per listener, 20 messages in flight, 1000 queued | A misbehaving device cannot exhaust the broker |

Without a certificate, there is no device listener (unless plain MQTT is turned on). MQTT-BRK-004 then fails with
a clear message.

## 3. Accounts

Admins manage device accounts in **Settings → MQTT device accounts** (`/api/v1/mqtt/accounts`).

| Account | May publish | May read |
|---|---|---|
| `otprobe-reader` | **nothing** | `#` and `$SYS/#`. Used by OTProbe; a new random password every start, never stored |
| one per device or gateway, e.g. `sensor01` | its own **topic prefix** only, e.g. `plant/line1/sensor01` and everything under it | **nothing** |

- **One sender per topic.** A prefix is plain topic levels: no `+` or `#`, no `$`, at most 10 levels. Prefixes may not
  overlap (`plant/line1` and `plant/line1/sensor01` cannot both exist; `422 mqtt-acl-too-broad`,
  `409 mqtt-prefix-overlap`). So the broker guarantees that every message on a topic comes from exactly one account.
- **Usernames:** lowercase letters, digits, `.`, `_`, `-`, 3–64 characters, not starting with `otprobe`.
- **The password is shown once**, on create and on **New password**. OTProbe stores only the Mosquitto hash.
- **Disable, Delete and New password take effect at once.** Mosquitto re-reads the files and disconnects that
  device. For a new password, OTProbe first removes the account (which disconnects the device), then writes it back
  with the new hash. A disabled device cannot log in again.
- Operators and approvers can see accounts and who is connected. Only admins can change them. Every change is
  audited:
  - `MQTT_ACCOUNT_CREATED`
  - `MQTT_ACCOUNT_UPDATED` (asset link, description)
  - `MQTT_ACCOUNT_DISABLED`
  - `MQTT_ACCOUNT_ENABLED`
  - `MQTT_ACCOUNT_PASSWORD_ROTATED`
  - `MQTT_ACCOUNT_DELETED`
- **Who is connected** comes from the broker's own log, which gives the account, the device's MQTT client id and its
  IP address. The console shows:
  - connected devices;
  - for each account, where it last connected from;
  - the last 20 refused logins (admins only), for example a wrong password or a disabled account.

## 4. Messages → assets

A message belongs to the **account allowed to publish its topic** (§3). Its asset is:

1. the asset **linked to the account**: choose it when you create the account, or later in the account list.
   Linking also moves the messages already received; or else
2. the asset whose IP address is the address the device **connects from**, if one has been discovered.

Topics with no asset show as **not linked** on the Telemetry page. They are stored, but rules run only on messages that
have an asset. The agentless probe's MQTT step reports the device connected from the asset's address:
- `mqtt.client_id`
- `mqtt.account`
- `mqtt.topics`
- `mqtt.broker`

**Payloads:**
- **JSON** is stored as it is: numbers, or objects such as `{"temperature": 72.4, "unit": "C"}`.
- **Other text** is stored as text.
- **Binary payloads** (for example Sparkplug B) and **messages over 16 KiB** are counted, not stored. They show as
  "not stored" on the broker panel.

Storage keeps the most recent `TELEMETRY_RETENTION` messages (10 000).

## 5. Telemetry rules

Rules in `rules/telemetry.yaml` match a **metric**, not a fixed device. With `topic: "#"`, a rule applies to every topic
whose message carries its evidence. Rules see each message as an object:

| Message | Rules see |
|---|---|
| `{"temperature": 72.4, "unit": "C"}` on any topic | `temperature: 72.4`, `unit: "C"` |
| `72.4` on `plant/line1/sensor01/temperature` | `temperature: 72.4` (named after the topic's last level) |
| `RUN` on `plant/line1/plc01/mode` | `mode: "RUN"` |
| anything | `mqtt.topic` as well |

| Rule | Check | Severity |
|---|---|---|
| TEL-TEMP-001 / 002 | `temperature` ≤ 80 / ≤ 95 | MEDIUM / CRITICAL |
| TEL-PRES-001 | `pressure` ≤ 6.0 | HIGH |
| TEL-PLC-001 | `mode` is RUN, and a status message at least every 30 s | HIGH |
| TEL-STALE-001 | **Telemetry source silent**: no message for 5 minutes from a device that has published | HIGH |

Staleness is checked per asset, on the topics that carry the rule's evidence: a temperature sensor never trips the PLC
rule. The next message closes the finding. To give one area its own thresholds, add a rule with a narrower topic
filter, for example `plant/line2/#`.

## 6. Broker checks

OTProbe checks its own broker. The results are shown in Settings → MQTT broker; they are not stored as findings
(decision L6-13).

| Rule | Check | Severity |
|---|---|---|
| `MQTT-BRK-001` | Anonymous access is refused: OTProbe tries to connect without a password at every start | CRITICAL |
| `MQTT-BRK-002` | No unencrypted listener | MEDIUM |
| `MQTT-BRK-003` | No account can publish to every topic | HIGH |
| `MQTT-BRK-004` | Server certificate valid for more than 30 days (fails if there is no certificate) | MEDIUM |

## 7. Network placement

- Devices need `8883/tcp` to the OTProbe machine, and nothing else.
- OTProbe never connects **out** to a device over MQTT; devices always connect in.
- Its own connection is to `127.0.0.1` only. That is why the broker code sits outside the network gate; a test proves
  that every bind and connect in it is loopback only.

## 8. Not built (yet)

| Item | Note |
|---|---|
| Mode B: read-only client of a plant's existing broker | Next MQTT step |
| Sparkplug B decoding | Binary payloads are counted, not stored |
| Gateways publishing for several assets under one account | One account maps to one asset; give each device its own account and prefix |
| Checking other brokers found on the network (anonymous login probe) | |
| "Account unused for 90 days" check, hourly re-check, raw/hourly retention | Retention is the existing most-recent-messages limit |
| Bridge from a plant broker | |

## 9. Testing

| Test | How |
|---|---|
| Broker locked down | Real Mosquitto started by OTProbe on 127.0.0.1. Checks: anonymous, unknown and plain-text logins refused; TLS only; all four checks pass; files `0600`; the log visible to admins only |
| Accounts | Admin only; password once and only its hash on disk; wildcard, `$`, overlapping and reserved names refused |
| Messages and rules | A real device (paho, TLS) publishes on and outside its topic: only its own arrives. Linking moves the earlier messages. Plain `97` → TEL-TEMP-002 CRITICAL; `40` → resolved; the probe's MQTT step names the device |
| Silent device | One message, then silence → TEL-STALE-001 open (window scaled down); the next message resolves it |
| Disconnects | Disable, new password and delete each disconnect the device at once, and the old credentials are refused |
| OTProbe cannot publish | Its own account publishes: nothing is delivered. Killing Mosquitto: it is restarted and the accounts still work |
| Fake sensor | `scripts/fake_sensor.py` publishes over TLS; a wrong password exits with "login refused" |
| Files and parsing (unit) | Hash format against `mosquitto_passwd`, prefix rules, ACL and config files, log lines, payload decoding |
| By hand | [TESTING_L6_MQTT.md](TESTING_L6_MQTT.md): the broker on your Mac, a fake sensor on a second machine |

Tests: `tests/live/test_mqtt_broker.py`, `tests/unit/test_mqtt_broker_files.py`. They need Mosquitto installed; tests
that need it are skipped without it.
