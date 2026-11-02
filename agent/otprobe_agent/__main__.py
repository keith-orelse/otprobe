"""OTProbe simulated agent runtime (Phase 1 skeleton).

Phase 3 implements: poll /sim/v1/hosts/agent-installs, spawn one Agent per installed host,
enroll -> heartbeat -> long-poll tasks -> collect local state -> upload evidence. Outbound HTTP only.
"""

import os
import time


def main() -> None:
    api = os.environ.get("OTPROBE_API_URL", "http://api:8000")
    print(f"[agent-runtime] skeleton: would poll {api}/sim/v1/hosts/agent-installs (no agents yet)", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
