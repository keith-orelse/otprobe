package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

var (
	errNoPackageManager = errors.New("no dpkg, rpm or apk found")
	errNoData           = errors.New("no data reported")
)

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}

// hashParts makes the host fingerprint: SHA-256 over stable machine identifiers. A cloned VM or moved disk changes it.
func hashParts(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}
