# Testing the bundled MQTT broker by hand (Mode A)

Run OTProbe's own MQTT broker on your Mac. Then send readings from a fake sensor, first on the Mac and then from a
second machine, and watch the findings open and close. Allow about 20 minutes.

You need:

- **This Mac**, set up as in [TESTING_L4.md](TESTING_L4.md) step 3 (HTTPS with `backend/tls/`);
- **Mosquitto:** `brew install mosquitto`;
- optionally, **a second machine** on the same network with Python 3, to act as a sensor.

## 1. Start OTProbe with the broker on

Use the usual start command from TESTING_L4.md with `MQTT_BROKER=bundled` added at the front:

```bash
cd ~/probing/backend
MQTT_BROKER=bundled DATABASE_URL=sqlite:///./otprobe-live.db OTPROBE_PUBLIC_URL=https://192.168.0.160:8000 \
  OTPROBE_TLS_CA_FILE=tls/otprobe-ca.pem AGENT_RELEASE_PUBKEY_FILE=../keys/otprobe-release.pub \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --ssl-certfile tls/otprobe-server.pem --ssl-keyfile tls/otprobe-server.key --reload
```

Replace `192.168.0.160` with your Mac's current IP address.

| # | Do | Expect |
|---|---|---|
| 1.1 | As **admin**: **Settings → MQTT broker** | **OK**, Mosquitto 2.x. "Devices connect to" `192.168.0.160:8883 (TLS)` |
| 1.2 | Same panel | Four checks, all **PASS** |
| 1.3 | **Download CA certificate** | You get `otprobe-ca.pem`, the same file as `backend/tls/otprobe-ca.pem` |

## 2. A sensor on the Mac

| # | Do | Expect |
|---|---|---|
| 2.1 | **MQTT device accounts**: name `sensor01`, prefix `plant/line1/sensor01`, **CREATE ACCOUNT** | A yellow box with the password and a ready-made **Test with** command. Copy the command |
| 2.2 | In a second terminal: `cd ~/probing` and paste the command, with `--host 127.0.0.1` | `connected … as sensor01`, then a reading every second |
| 2.3 | **Settings** | sensor01 **ONLINE**, from `127.0.0.1`, last message "0s ago" |
| 2.4 | **MQTT Telemetry** | `plant/line1/sensor01/temperature`, account `sensor01`, asset **not linked**, a trend line |

## 3. Link it to an asset and trigger the rules

| # | Do | Expect |
|---|---|---|
| 3.1 | Settings → sensor01 → **Asset** list: pick any asset (for example your laptop) | Telemetry shows that asset on the topic |
| 3.2 | Stop the sensor (Ctrl+C). Run the same command with `--value 97` | **Findings**: TEL-TEMP-001 WARNING and **TEL-TEMP-002 CRITICAL** on that asset. **Audit Logs**: `TELEMETRY_THRESHOLD_EXCEEDED` |
| 3.3 | Stop it, then run it again with `--value 42` | Both findings **RESOLVED** |
| 3.4 | Stop it and wait 5 minutes | **TEL-STALE-001** "Telemetry source silent" opens |
| 3.5 | Start it again | TEL-STALE-001 **RESOLVED** |

## 4. Account controls

| # | Do | Expect |
|---|---|---|
| 4.1 | With the sensor running: **Disable** | Within a second the sensor prints `disconnected` and then `not connected, waiting…`; the account shows BLOCKED. **MQTT broker → Refused logins** lists its retries |
| 4.2 | **Enable** | The sensor reconnects by itself |
| 4.3 | **New password** | The sensor is disconnected and cannot log back in. Start it with the new password: it works |
| 4.4 | Run the sensor with `--topic plant/line1/sensor02/temperature` | It says it sends, but nothing new appears on Telemetry: the broker drops messages outside the account's prefix |

## 5. From a second machine (optional)

On the other machine:

```bash
pip install paho-mqtt
```

Copy `scripts/fake_sensor.py` and the downloaded `otprobe-ca.pem` to it, then run:

```bash
python fake_sensor.py --host 192.168.0.160 --ca otprobe-ca.pem --username sensor01 --password '<password>' \
  --topic plant/line1/sensor01/temperature --value 42
```

| # | Expect |
|---|---|
| 5.1 | Connected. Settings shows that machine's IP address |
| 5.2 | If you unlink the account (Asset → "not linked") and that machine was discovered as an asset, the readings go to it by its address |

If it cannot connect, the Mac's firewall is probably blocking port 8883. Check System Settings → Network → Firewall.

## 6. Clean up

Delete the account (the sensor is disconnected). To turn the broker off, start OTProbe without `MQTT_BROKER=bundled`.

---

| Symptom | Cause |
|---|---|
| Panel says "Mosquitto is not installed" | `brew install mosquitto`, then restart OTProbe |
| "Devices connect to: nothing", MQTT-BRK-004 FAIL | `OTPROBE_TLS_CA_FILE` is not set, or `otprobe-server.pem/.key` are not next to it |
| Sensor: `certificate verify failed` | The server certificate does not name the IP used in `--host`: re-run `scripts/make_lab_tls.py` with the Mac's current IP. **This replaces the CA, so installed agents must be reinstalled** |
| Sensor: `login refused` | Wrong password, or the account is disabled |
| Topic stays "not linked" | Link the account to an asset in Settings |
