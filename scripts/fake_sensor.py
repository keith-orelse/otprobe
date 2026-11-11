"""A fake MQTT sensor for testing OTProbe's bundled broker (docs/TESTING_L6_MQTT.md). Not part of the product.

    backend/.venv/bin/python scripts/fake_sensor.py --host 192.168.0.160 --ca backend/tls/otprobe-ca.pem \\
        --username sensor01 --password '<from OTProbe>' --topic plant/line1/sensor01/temperature --value 42

Publishes a reading every --interval seconds (the value moves by up to +/- --jitter). Use --value 97 for a "too
hot" reading, and stop it (Ctrl+C) to see the "sensor silent" finding after five minutes. --json sends
{"temperature": 42.1, "unit": "C"} instead of a plain number. The password can also come from MQTT_PASSWORD.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import ssl
import sys
import time

import paho.mqtt.client as mqtt


def parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--host", default="127.0.0.1", help="the OTProbe machine")
    p.add_argument("--port", type=int, default=8883)
    p.add_argument("--ca", help="OTProbe's CA certificate (Settings -> MQTT broker -> Download CA). Needed for TLS")
    p.add_argument("--no-tls", action="store_true", help="plain MQTT, only if an admin turned MQTT_PLAIN_PORT on")
    p.add_argument("--username", required=True)
    p.add_argument("--password", default=os.environ.get("MQTT_PASSWORD"))
    p.add_argument("--topic", required=True, help="must be under the account's topic prefix")
    p.add_argument("--value", type=float, default=42.0)
    p.add_argument("--jitter", type=float, default=1.0)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--count", type=int, default=0, help="stop after this many readings (0 = run until Ctrl+C)")
    p.add_argument("--json", action="store_true", help='send {"<metric>": value, "unit": ...} instead of a number')
    p.add_argument("--unit", default="C")
    p.add_argument("--client-id", default="")
    args = p.parse_args(argv)
    if not args.password:
        p.error("--password (or MQTT_PASSWORD) is required")
    if not args.no_tls and not args.ca:
        p.error("--ca is required for TLS (or --no-tls for a plain listener)")
    return args


def main(argv: list[str]) -> int:
    args = parse(argv)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.client_id or f"fake-{args.username}",
                         protocol=mqtt.MQTTv311)
    client.username_pw_set(args.username, args.password)
    if not args.no_tls:
        client.tls_set(ca_certs=args.ca, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    result: dict[str, object] = {}
    client.on_connect = lambda c, u, f, reason, p: result.setdefault("connect", reason)
    client.on_disconnect = lambda c, u, f, reason, p: print(f"disconnected: {reason}", flush=True)
    try:
        client.connect(args.host, args.port, keepalive=30)
    except (OSError, ssl.SSLError) as exc:
        print(f"cannot reach {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2
    client.loop_start()
    deadline = time.monotonic() + 10
    while "connect" not in result and time.monotonic() < deadline:
        time.sleep(0.05)
    reason = result.get("connect")
    if reason is None or reason.is_failure:
        print(f"login refused: {reason or 'no answer'} (check the username, password and that the account is enabled)",
              file=sys.stderr)
        return 3
    print(f"connected to {args.host}:{args.port} as {args.username}", flush=True)
    metric = args.topic.rsplit("/", 1)[-1]
    sent = 0
    try:
        while not args.count or sent < args.count:
            value = round(args.value + random.uniform(-args.jitter, args.jitter), 2)
            payload = json.dumps({metric: value, "unit": args.unit}) if args.json else str(value)
            if not client.is_connected():          # broker restarting, or the account was disabled
                print("not connected, waiting for the broker...", flush=True)
                time.sleep(max(args.interval, 2))
                continue
            info = client.publish(args.topic, payload, qos=1)
            try:
                info.wait_for_publish(5)
            except RuntimeError:
                continue                           # lost the connection mid-send: paho reconnects, try again
            sent += 1
            print(f"{args.topic} = {payload}", flush=True)
            if not args.count or sent < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()
        client.loop_stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
