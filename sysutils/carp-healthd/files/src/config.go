package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type rawCheck struct {
	UUID   string
	Fields map[string]string
}

type rawHealth struct {
	Fields map[string]string
	Checks []rawCheck
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (Config, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	interfaces := map[string]string{}
	var vips []map[string]string
	var health *rawHealth

	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return Config{}, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "interfaces":
			got, err := decodeInterfaces(dec, start)
			if err != nil {
				return Config{}, err
			}
			for k, v := range got {
				interfaces[k] = v
			}
		case "virtualip":
			got, err := decodeVirtualIP(dec, start)
			if err != nil {
				return Config{}, err
			}
			vips = append(vips, got...)
		case "CarpHealth":
			got, err := decodeHealth(dec, start)
			if err != nil {
				return Config{}, err
			}
			health = &got
		}
	}

	if health == nil {
		return Config{
			Enabled:           false,
			Interval:          time.Second,
			IntervalSeconds:   1,
			FailureThreshold:  2,
			RecoveryThreshold: 2,
			Signature:         "disabled",
		}, nil
	}

	cfg := Config{
		Enabled:           parseBool(health.Fields["enabled"], false),
		IntervalSeconds:   parseInt(health.Fields["interval"], 1, 1, 60),
		FailureThreshold:  parseInt(health.Fields["failure_threshold"], 2, 1, 20),
		RecoveryThreshold: parseInt(health.Fields["recovery_threshold"], 2, 1, 20),
	}
	cfg.Interval = time.Duration(cfg.IntervalSeconds) * time.Second

	for _, vip := range vips {
		if strings.ToLower(strings.TrimSpace(vip["mode"])) != "carp" {
			continue
		}
		logical := strings.TrimSpace(vip["interface"])
		vhid := parseInt(vip["vhid"], 0, 0, 255)
		if vhid == 0 {
			continue
		}
		cfg.CarpVhids = append(cfg.CarpVhids, CarpVhid{
			Interface: logical,
			Device:    interfaces[logical],
			VHID:      vhid,
			Advskew:   parseInt(vip["advskew"], 0, 0, 254),
		})
	}

	for _, raw := range health.Checks {
		f := raw.Fields
		if !parseBool(f["enabled"], true) {
			continue
		}
		name := strings.TrimSpace(f["name"])
		logical := strings.TrimSpace(f["interface"])
		scope := strings.ToLower(strings.TrimSpace(f["scope"]))
		switch scope {
		case "interface", "all_carp", "vhid", "vhid_group", "global":
		default:
			scope = "global"
		}
		if scope == "" {
			scope = "global"
		}
		uuid := strings.TrimSpace(raw.UUID)
		if uuid == "" {
			uuid = name
		}
		check := Check{
			UUID:                       uuid,
			Name:                       name,
			Interface:                  logical,
			Device:                     strings.TrimSpace(interfaces[logical]),
			Target:                     parseIP(f["target"], 4),
			Scope:                      scope,
			FailureAdvskew:             parseInt(f["failure_advskew"], failoverAdvskew, 1, failoverAdvskew),
			FallbackIPv4Target:         parseIP(f["fallback_ipv4_target"], 4),
			FallbackIPv4Gateway:        parseIP(f["fallback_ipv4_gateway"], 4),
			FallbackIPv6Target:         parseIP(f["fallback_ipv6_target"], 6),
			FallbackIPv6Gateway:        parseIP(f["fallback_ipv6_gateway"], 6),
			FallbackIPv4DefaultGateway: parseIP(f["fallback_ipv4_default_gateway"], 4),
			FallbackIPv6DefaultGateway: parseIP(f["fallback_ipv6_default_gateway"], 6),
			BackupIPv4DefaultGateway:   parseIP(f["backup_ipv4_default_gateway"], 4),
			BackupIPv6DefaultGateway:   parseIP(f["backup_ipv6_default_gateway"], 6),
		}
		if scope == "vhid" {
			check.VHID = parseInt(f["vhid"], 0, 0, 255)
			if check.VHID > 0 {
				check.VHIDTargets = []VhidTarget{{Interface: logical, VHID: check.VHID}}
			}
		} else if scope == "vhid_group" {
			check.VHIDTargets = parseVhidTargets(f["vhid_targets"])
		}
		cfg.Checks = append(cfg.Checks, check)
	}

	sig, err := configSignature(cfg)
	if err != nil {
		return Config{}, err
	}
	cfg.Signature = sig
	return cfg, nil
}

func decodeInterfaces(dec *xml.Decoder, root xml.StartElement) (map[string]string, error) {
	out := map[string]string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			fields, err := decodeSimpleElement(dec, t)
			if err != nil {
				return nil, err
			}
			out[t.Name.Local] = strings.TrimSpace(fields["if"])
		case xml.EndElement:
			if t.Name == root.Name {
				return out, nil
			}
		}
	}
}

func decodeVirtualIP(dec *xml.Decoder, root xml.StartElement) ([]map[string]string, error) {
	var out []map[string]string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "vip" {
				fields, err := decodeSimpleElement(dec, t)
				if err != nil {
					return nil, err
				}
				out = append(out, fields)
			} else {
				if err := dec.Skip(); err != nil {
					return nil, err
				}
			}
		case xml.EndElement:
			if t.Name == root.Name {
				return out, nil
			}
		}
	}
}

func decodeHealth(dec *xml.Decoder, root xml.StartElement) (rawHealth, error) {
	out := rawHealth{Fields: map[string]string{}}
	for {
		tok, err := dec.Token()
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "checks" {
				checks, err := decodeChecks(dec, t)
				if err != nil {
					return out, err
				}
				out.Checks = checks
			} else {
				var value string
				if err := dec.DecodeElement(&value, &t); err != nil {
					return out, err
				}
				out.Fields[t.Name.Local] = strings.TrimSpace(value)
			}
		case xml.EndElement:
			if t.Name == root.Name {
				return out, nil
			}
		}
	}
}

func decodeChecks(dec *xml.Decoder, root xml.StartElement) ([]rawCheck, error) {
	var out []rawCheck
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "check" {
				if err := dec.Skip(); err != nil {
					return nil, err
				}
				continue
			}
			fields, err := decodeSimpleElement(dec, t)
			if err != nil {
				return nil, err
			}
			uuid := ""
			for _, attr := range t.Attr {
				if attr.Name.Local == "uuid" {
					uuid = attr.Value
					break
				}
			}
			out = append(out, rawCheck{UUID: uuid, Fields: fields})
		case xml.EndElement:
			if t.Name == root.Name {
				return out, nil
			}
		}
	}
}

func decodeSimpleElement(dec *xml.Decoder, root xml.StartElement) (map[string]string, error) {
	out := map[string]string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := dec.DecodeElement(&value, &t); err != nil {
				return nil, err
			}
			out[t.Name.Local] = strings.TrimSpace(value)
		case xml.EndElement:
			if t.Name == root.Name {
				return out, nil
			}
		}
	}
}

func parseBool(value string, def bool) bool {
	if strings.TrimSpace(value) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseInt(value string, def, min, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		n = def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func parseIP(value string, version int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	if version == 4 && !addr.Is4() {
		return ""
	}
	if version == 6 && !addr.Is6() {
		return ""
	}
	return addr.String()
}

func parseVhidTargets(value string) []VhidTarget {
	var out []VhidTarget
	seen := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		i := strings.LastIndexByte(item, ':')
		if i <= 0 || i == len(item)-1 {
			continue
		}
		logical := strings.TrimSpace(item[:i])
		vhid := parseInt(item[i+1:], 0, 0, 255)
		if logical == "" || vhid == 0 {
			continue
		}
		target := VhidTarget{Interface: logical, VHID: vhid}
		if !seen[target.Key()] {
			seen[target.Key()] = true
			out = append(out, target)
		}
	}
	return out
}

func resolveVhidTargets(check Check, cfg Config) []VhidTarget {
	var candidates []VhidTarget
	switch check.Scope {
	case "interface":
		for _, carp := range cfg.CarpVhids {
			if carp.Interface == check.Interface {
				candidates = append(candidates, VhidTarget{Interface: carp.Interface, VHID: carp.VHID})
			}
		}
	case "all_carp":
		for _, carp := range cfg.CarpVhids {
			candidates = append(candidates, VhidTarget{Interface: carp.Interface, VHID: carp.VHID})
		}
	case "vhid", "vhid_group":
		candidates = append(candidates, check.VHIDTargets...)
	default:
		return nil
	}
	seen := map[string]bool{}
	out := make([]VhidTarget, 0, len(candidates))
	for _, target := range candidates {
		if !seen[target.Key()] {
			seen[target.Key()] = true
			out = append(out, target)
		}
	}
	return out
}

func findCarpVhid(cfg Config, logical string, vhid int) (CarpVhid, bool) {
	for _, carp := range cfg.CarpVhids {
		if carp.Interface == logical && carp.VHID == vhid {
			return carp, true
		}
	}
	return CarpVhid{}, false
}

func pythonCanonicalJSON(value any) ([]byte, error) {
	var buf strings.Builder
	var write func(any) error
	write = func(v any) error {
		switch x := v.(type) {
		case nil:
			buf.WriteString("null")
		case bool:
			if x {
				buf.WriteString("true")
			} else {
				buf.WriteString("false")
			}
		case int:
			buf.WriteString(strconv.Itoa(x))
		case string:
			encoded, err := json.Marshal(x)
			if err != nil {
				return err
			}
			buf.Write(encoded)
		case []any:
			buf.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					buf.WriteString(", ")
				}
				if err := write(item); err != nil {
					return err
				}
			}
			buf.WriteByte(']')
		case [][]any:
			items := make([]any, len(x))
			for i := range x {
				items[i] = x[i]
			}
			return write(items)
		case []map[string]any:
			items := make([]any, len(x))
			for i := range x {
				items[i] = x[i]
			}
			return write(items)
		case map[string]any:
			keys := make([]string, 0, len(x))
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			buf.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					buf.WriteString(", ")
				}
				encoded, err := json.Marshal(key)
				if err != nil {
					return err
				}
				buf.Write(encoded)
				buf.WriteString(": ")
				if err := write(x[key]); err != nil {
					return err
				}
			}
			buf.WriteByte('}')
		default:
			return fmt.Errorf("unsupported canonical JSON type %T", v)
		}
		return nil
	}
	if err := write(value); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func configSignature(cfg Config) (string, error) {
	checks := make([]map[string]any, 0, len(cfg.Checks))
	for _, c := range cfg.Checks {
		targets := make([][]any, 0, len(c.VHIDTargets))
		for _, t := range c.VHIDTargets {
			targets = append(targets, []any{t.Interface, t.VHID})
		}
		checks = append(checks, map[string]any{
			"uuid": c.UUID, "name": c.Name, "interface": c.Interface, "device": c.Device,
			"target": c.Target, "scope": c.Scope, "vhid": c.VHID, "vhid_targets": targets,
			"failure_advskew":      c.FailureAdvskew,
			"fallback_ipv4_target": c.FallbackIPv4Target, "fallback_ipv4_gateway": c.FallbackIPv4Gateway,
			"fallback_ipv6_target": c.FallbackIPv6Target, "fallback_ipv6_gateway": c.FallbackIPv6Gateway,
			"fallback_ipv4_default_gateway": c.FallbackIPv4DefaultGateway,
			"fallback_ipv6_default_gateway": c.FallbackIPv6DefaultGateway,
			"backup_ipv4_default_gateway":   c.BackupIPv4DefaultGateway,
			"backup_ipv6_default_gateway":   c.BackupIPv6DefaultGateway,
		})
	}
	vhids := make([]map[string]any, 0, len(cfg.CarpVhids))
	for _, c := range cfg.CarpVhids {
		vhids = append(vhids, map[string]any{
			"interface": c.Interface, "device": c.Device, "vhid": c.VHID, "advskew": c.Advskew,
		})
	}
	canonical := map[string]any{
		"enabled": cfg.Enabled, "interval": cfg.IntervalSeconds,
		"failure_threshold": cfg.FailureThreshold, "recovery_threshold": cfg.RecoveryThreshold,
		"checks": checks, "carp_vhids": vhids,
	}
	data, err := pythonCanonicalJSON(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal config signature: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
