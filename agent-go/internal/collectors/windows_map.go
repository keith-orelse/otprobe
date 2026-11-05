package collectors

// Windows JSON-to-evidence mapping (untagged so it is unit-tested on any build host).

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

func MapWindowsOS(raw json.RawMessage) (map[string]interface{}, error) {
	var o map[string]interface{}
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	caption := strings.TrimSpace(str(o["caption"]))
	build := str(o["build"])
	if ubr := str(o["ubr"]); ubr != "" {
		build += "." + ubr
	}
	version := str(o["displayVersion"])
	if version == "" {
		version = str(o["releaseId"])
	}
	return map[string]interface{}{"family": "windows", "name": caption,
		"product": strings.TrimSpace(strings.TrimPrefix(caption, "Microsoft ")), "version": version, "build": build,
		"server": str(o["productType"]) != "1"}, nil
}

func MapWindowsFirewall(raw json.RawMessage) (map[string]interface{}, error) {
	profiles := AsList(raw)
	if len(profiles) == 0 {
		return nil, errNoData
	}
	on, off := 0, 0
	states := map[string]string{}
	inbound := ""
	for _, p := range profiles {
		name := strings.ToLower(str(p["name"]))
		if b, _ := p["enabled"].(bool); b {
			states[name], on = "on", on+1
		} else {
			states[name], off = "off", off+1
		}
		inbound = strings.ToLower(strings.Replace(str(p["inbound"]), "NotConfigured", "Block", 1))
	}
	state := "partial"
	if off == 0 {
		state = "enabled"
	} else if on == 0 {
		state = "disabled"
	}
	return map[string]interface{}{"state": state, "profiles": states, "defaultInbound": inbound}, nil
}

func MapWindowsAntivirus(raw json.RawMessage) (map[string]interface{}, error) {
	var a struct {
		Defender       map[string]interface{} `json:"defender"`
		SecurityCenter json.RawMessage        `json:"securityCenter"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if a.Defender != nil {
		state := "stopped"
		if b, _ := a.Defender["service"].(bool); b {
			state = "running"
		}
		return map[string]interface{}{"product": "Microsoft Defender Antivirus", "state": state,
			"realtime": a.Defender["realtime"], "signature_age_days": a.Defender["signatureAge"]}, nil
	}
	for _, p := range AsList(a.SecurityCenter) {
		n, _ := p["state"].(float64)
		state := "stopped"
		if (int(n)>>12)&0xF == 1 {
			state = "running"
		}
		return map[string]interface{}{"product": str(p["name"]), "state": state}, nil
	}
	return nil, errNoData // servers without Defender or Security Center: unknown, never "stopped"
}

func MapWindowsHotfixes(raw json.RawMessage, now time.Time) map[string]interface{} {
	var ids, dates []string
	for _, h := range AsList(raw) {
		if id := str(h["id"]); id != "" {
			ids = append(ids, id)
		}
		if d := str(h["installedOn"]); d != "" {
			dates = append(dates, d)
		}
	}
	out := map[string]interface{}{"installed": ids}
	if days, ok := ParseHotfixDays(dates, now); ok {
		out["last_installed_days"] = days
	}
	// "missing" needs a Windows Update catalog (WSUS or offline cab: open question O2). Without one it is absent
	// and WIN-PATCH-001 evaluates to UNKNOWN.
	return out
}

func MapWindowsSoftware(raw json.RawMessage) []map[string]interface{} {
	seen := map[string]bool{}
	var out []map[string]interface{}
	for _, s := range AsList(raw) {
		key := str(s["name"]) + "|" + str(s["version"])
		if str(s["name"]) == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, map[string]interface{}{"name": str(s["name"]), "version": str(s["version"]),
			"publisher": str(s["publisher"])})
	}
	return out
}

func MapWindowsAdmins(raw json.RawMessage) map[string]interface{} {
	members := AsList(raw)
	enabled := 0
	for _, m := range members {
		if b, ok := m["enabled"].(bool); !ok || b {
			enabled++
		}
	}
	return map[string]interface{}{"members": members, "enabled_count": enabled}
}

func decodeUTF16(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}

func str(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}
