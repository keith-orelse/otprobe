#!/bin/sh
# Build every agent target, then write SHA256SUMS and manifest.json (docs/GO_AGENT.md §1).
#   ./build.sh 1.2.0            -> dist/1.2.0/
# Legacy builds (Windows 7 / Server 2008 R2-2012, Linux kernels 2.6.32-3.1) use Go 1.20.14:
#   go install golang.org/dl/go1.20.14@latest && go1.20.14 download
# Sign afterwards with:  backend/.venv/bin/python scripts/sign_release.py agent-go/dist/1.2.0 --key <release key>
set -eu
VERSION="${1:?usage: build.sh VERSION}"
OUT="dist/$VERSION"
LEGACY_GO="${LEGACY_GO:-$HOME/go/bin/go1.20.14}"
rm -rf "$OUT" && mkdir -p "$OUT"

# build_id  goos  goarch  variant  [goarm]
TARGETS="windows-amd64 windows amd64 modern
windows-arm64 windows arm64 modern
windows-386 windows 386 modern
windows-legacy-amd64 windows amd64 legacy
windows-legacy-386 windows 386 legacy
linux-amd64 linux amd64 modern
linux-arm64 linux arm64 modern
linux-386 linux 386 modern
linux-armv7 linux arm modern 7
linux-armv6 linux arm modern 6
linux-legacy-amd64 linux amd64 legacy
linux-legacy-386 linux 386 legacy
darwin-amd64 darwin amd64 modern
darwin-arm64 darwin arm64 modern"

echo "$TARGETS" | while read -r id goos goarch variant goarm; do
  gobin=go
  if [ "$variant" = legacy ]; then gobin="$LEGACY_GO"; fi
  ext=""; [ "$goos" = windows ] && ext=".exe"
  file="otprobe-agent-$VERSION-$id$ext"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="${goarm:-}" "$gobin" build -trimpath \
    -ldflags "-s -w -buildid= -X otprobe/agent/internal/collectors.Version=$VERSION -X otprobe/agent/internal/agent.Variant=$variant" \
    -o "$OUT/$file" ./cmd/otprobe-agent
  echo "built $file"
done

cd "$OUT"
shasum -a 256 otprobe-agent-* > SHA256SUMS 2>/dev/null || sha256sum otprobe-agent-* > SHA256SUMS
python3 - "$VERSION" <<'PY'
import json, os, sys
version = sys.argv[1]
min_os = {"windows-legacy": "Windows 7 SP1 / Server 2008 R2", "windows": "Windows 10 / Server 2016",
          "linux-legacy": "kernel 2.6.32", "linux": "kernel 3.2", "darwin": "macOS 12"}
builds = []
for line in open("SHA256SUMS"):
    sha, name = line.split()
    bid = name.removeprefix(f"otprobe-agent-{version}-").removesuffix(".exe")
    parts = bid.split("-")
    variant = "legacy" if "legacy" in parts else "modern"
    os_, arch = parts[0], parts[-1]
    builds.append({"id": bid, "file": name, "os": os_, "arch": arch, "variant": variant, "sha256": sha,
                   "size": os.path.getsize(name),
                   "minOs": min_os[f"{os_}-legacy" if variant == "legacy" else os_]})
json.dump({"version": version, "builds": builds}, open("manifest.json", "w"), indent=2)
print(f"manifest: {len(builds)} builds")
PY
