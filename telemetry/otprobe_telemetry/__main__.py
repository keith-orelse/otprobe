"""OTProbe telemetry simulator (Phase 1 skeleton).

Phase 5 implements deterministic (SEED) sensor/PLC telemetry published via POST /sim/v1/mqtt/publish.
"""

import os
import time


def main() -> None:
    api = os.environ.get("OTPROBE_API_URL", "http://api:8000")
    print(f"[telemetry-sim] skeleton: would publish to {api}/sim/v1/mqtt/publish", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
