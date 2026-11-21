package frpconf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// ParseServer decodes frps TOML into the managed model.
func ParseServer(raw []byte) (*ServerConfig, error) {
	cfg := &ServerConfig{}
	if err := toml.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseClient decodes frpc TOML into the managed model. Range-template
// configs (parseNumberRangePair) are expanded into the same proxy list, so
// every forwarded port stays visible and editable.
func ParseClient(raw []byte) (*ClientConfig, error) {
	cfg := &ClientConfig{}
	err := toml.Unmarshal(raw, cfg)
	if err == nil {
		return cfg, nil
	}
	if rangeCfg, rerr := parseRangeClient(raw); rerr == nil {
		return rangeCfg, nil
	}
	return nil, err
}

// ReadServer reads and parses an frps config file from disk.
func ReadServer(path string) (*ServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseServer(raw)
}

// ReadClient reads and parses an frpc config file from disk.
func ReadClient(path string) (*ClientConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseClient(raw)
}

// Style classifies how a config file relates to the managed model.
type Style uint8

const (
	// StyleManaged: valid TOML. Structured edits are safe for every valid
	// config: keys outside the modeled subset are carried through by
	// MergeServer/MergeClient instead of being dropped.
	StyleManaged Style = iota
	// StyleAdvanced: the file exists but is not parseable TOML. The panel
	// routes these (and any write-gate failures) to the raw-text editor.
	StyleAdvanced
	// StyleTemplate: contains Go template directives ({{ ... }}), as written
	// by the CLI's compact mode for very large port ranges. frp renders
	// these at load time; the suite never rewrites them structurally.
	StyleTemplate
)

func (s Style) String() string {
	switch s {
	case StyleAdvanced:
		return "advanced"
	case StyleTemplate:
		return "template"
	default:
		return "managed"
	}
}

// Classify inspects raw config bytes and reports the safest editing mode.
// unknown is the first key (dotted path) outside the modeled subset. It is
// informational only: every parseable TOML config can be edited structurally
// because ComposeServer/ComposeClient merge unknown keys back into the file.
func Classify(raw []byte, kind Kind) (Style, string, error) {
	if bytes.Contains(raw, []byte("{{")) {
		// A parseNumberRangePair template is a first-class, structurally
		// editable config — not raw-only. Anything else that still contains
		// template directives remains StyleTemplate.
		if stripped, _, ok := stripRangeBlocks(raw); ok {
			var m map[string]any
			if err := toml.Unmarshal(stripped, &m); err == nil {
				var unknown string
				if kind == KindServer {
					unknown, _ = classifyServer(m)
				} else {
					unknown, _ = classifyClient(m)
				}
				return StyleManaged, unknown, nil
			}
		}
		return StyleTemplate, "", nil
	}
	var m map[string]any
	if err := toml.Unmarshal(raw, &m); err != nil {
		return StyleAdvanced, "", fmt.Errorf("classify: %w", err)
	}
	var unknown string
	if kind == KindServer {
		unknown, _ = classifyServer(m)
	} else {
		unknown, _ = classifyClient(m)
	}
	return StyleManaged, unknown, nil
}

// Known key sets exactly match what the canonical renderers emit. A key
// outside these sets sets `unknown`, which makes ComposeServer/ComposeClient
// take the merge path and preserve it. It never locks the structured editor.
var (
	serverTopKeys = map[string]bool{
		"bindAddr": true, "bindPort": true, "proxyBindAddr": true, "quicBindPort": true, "kcpBindPort": true,
		"transport": true, "auth": true, "webServer": true,
	}
	serverTransportKeys = map[string]bool{
		"quic": true, "heartbeatTimeout": true, "maxPoolCount": true, "tcpMux": true,
		"tcpMuxKeepaliveInterval": true, "tcpKeepalive": true,
	}
	clientTopKeys = map[string]bool{
		"serverAddr": true, "serverPort": true, "user": true, "loginFailExit": true,
		"auth": true, "transport": true, "webServer": true, "proxies": true,
	}
	clientTransportKeys = map[string]bool{
		"protocol": true, "tcpMux": true, "tcpMuxKeepaliveInterval": true,
		"dialServerTimeout": true, "dialServerKeepalive": true, "poolCount": true,
		"heartbeatInterval": true, "heartbeatTimeout": true, "tls": true, "quic": true,
	}
	quicKeys = map[string]bool{
		"keepalivePeriod": true, "maxIdleTimeout": true, "maxIncomingStreams": true,
	}
	authKeys  = map[string]bool{"method": true, "token": true}
	proxyKeys = map[string]bool{
		"name": true, "type": true, "localIP": true, "localPort": true,
		"remotePort": true, "transport": true,
	}
	proxyTransportKeys = map[string]bool{"useEncryption": true, "useCompression": true}
)

func firstUnknown(m map[string]any, allowed map[string]bool, path string) (string, bool) {
	for k := range m {
		if !allowed[k] {
			return path + k, false
		}
	}
	return "", true
}

func classifyTable(v any, allowed map[string]bool, path string) (map[string]any, string, bool) {
	sub, ok := v.(map[string]any)
	if !ok {
		return nil, "", true // scalar at this level: nothing more to check
	}
	bad, ok := firstUnknown(sub, allowed, path)
	if !ok {
		return nil, bad, false
	}
	return sub, "", true
}

func classifyServer(m map[string]any) (string, bool) {
	for k, v := range m {
		if !serverTopKeys[k] {
			return k, false
		}
		switch k {
		case "transport":
			sub, bad, ok := classifyTable(v, serverTransportKeys, "transport.")
			if !ok {
				return bad, false
			}
			if sub != nil {
				if qsub, ok2 := sub["quic"].(map[string]any); ok2 {
					if bad, ok := firstUnknown(qsub, quicKeys, "transport.quic."); !ok {
						return bad, false
					}
				}
			}
		case "auth":
			if _, bad, ok := classifyTable(v, authKeys, "auth."); !ok {
				return bad, false
			}
		case "webServer":
			if _, bad, ok := classifyTable(v, webServerKeys, "webServer."); !ok {
				return bad, false
			}
		}
	}
	return "", true
}

func classifyClient(m map[string]any) (string, bool) {
	for k, v := range m {
		if !clientTopKeys[k] {
			return k, false
		}
		switch k {
		case "auth":
			if _, bad, ok := classifyTable(v, authKeys, "auth."); !ok {
				return bad, false
			}
		case "webServer":
			if _, bad, ok := classifyTable(v, webServerKeys, "webServer."); !ok {
				return bad, false
			}
		case "transport":
			sub, bad, ok := classifyTable(v, clientTransportKeys, "transport.")
			if !ok {
				return bad, false
			}
			if sub != nil {
				if tsub, ok := sub["tls"].(map[string]any); ok {
					if bad, ok := firstUnknown(tsub, tlsKeys, "transport.tls."); !ok {
						return bad, false
					}
				}
				if qsub, ok := sub["quic"].(map[string]any); ok {
					if bad, ok := firstUnknown(qsub, quicKeys, "transport.quic."); !ok {
						return bad, false
					}
				}
			}
		case "proxies":
			arr, ok := v.([]any)
			if !ok {
				continue
			}
			for i, e := range arr {
				pm, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if bad, ok := firstUnknown(pm, proxyKeys, fmt.Sprintf("proxies[%d].", i)); !ok {
					return bad, false
				}
				if pt, ok := pm["transport"].(map[string]any); ok {
					if bad, ok := firstUnknown(pt, proxyTransportKeys, fmt.Sprintf("proxies[%d].transport.", i)); !ok {
						return bad, false
					}
				}
			}
		}
	}
	return "", true
}

// webServerKeys is used by both kinds.
var webServerKeys = map[string]bool{"addr": true, "port": true, "user": true, "password": true}

// tlsKeys covers the one TLS field the canonical client renderer emits.
var tlsKeys = map[string]bool{"enable": true}

// ListConfigs returns the .toml basenames (without extension) in a config dir.
// These are the valid systemd instance names for frps@*/frpc@*.
func ListConfigs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".toml") {
			names = append(names, strings.TrimSuffix(name, ".toml"))
		}
	}
	return names, nil
}

// UsedServerPorts scans a server config dir and collects every listen port
// (bindPort plus any quic/kcp bind ports). The panel uses it to refuse a new
// instance that would collide with an existing one — same semantics as the
// CLI's is_port_free grep scan.
func UsedServerPorts(dir string) (map[int]bool, error) {
	used := map[int]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return used, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m struct {
			BindPort     int `toml:"bindPort"`
			QUICBindPort int `toml:"quicBindPort"`
			KCPBindPort  int `toml:"kcpBindPort"`
		}
		if toml.Unmarshal(raw, &m) == nil {
			for _, p := range []int{m.BindPort, m.QUICBindPort, m.KCPBindPort} {
				if p > 0 {
					used[p] = true
				}
			}
		}
	}
	return used, nil
}

// UsedClientRemotePorts scans a client config dir and collects every proxy
// remotePort (the port occupied on the frps side).
func UsedClientRemotePorts(dir string) (map[int]bool, error) {
	used := map[int]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return used, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		cfg, err := ParseClient(raw)
		if err != nil {
			continue
		}
		for _, p := range cfg.Proxies {
			if p.RemotePort > 0 {
				used[p.RemotePort] = true
			}
		}
	}
	return used, nil
}

// UsedWebServerPorts scans a config dir and collects every webServer.port it
// can parse, so allocators never collide across instances.
func UsedWebServerPorts(dir string) (map[int]bool, error) {
	used := map[int]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return used, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m struct {
			WebServer WebServer `toml:"webServer"`
		}
		if toml.Unmarshal(raw, &m) == nil && m.WebServer.Port > 0 {
			used[m.WebServer.Port] = true
			continue
		}
		// Range-template configs: parse the non-template remainder.
		if cfg, perr := parseRangeClient(raw); perr == nil && cfg.WebServer.Port > 0 {
			used[cfg.WebServer.Port] = true
		}
	}
	return used, nil
}
