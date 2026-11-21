// Structured edits for configs that carry keys outside the canonical model.
//
// The panel used to refuse these files and force the raw editor. That made
// ordinary FRP configs (a [log] block, transport.tls settings, plugins, …)
// effectively uneditable. ComposeServer/ComposeClient now use the merge path
// whenever Classify reports an unknown key: managed fields are updated in the
// parsed TOML tree and every other key is written back untouched.
package frpconf

import (
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// ComposeServer renders an existing server config, preserving any keys the
// canonical renderer does not know about.
func ComposeServer(raw []byte, c *ServerConfig) ([]byte, error) {
	_, unknown, err := Classify(raw, KindServer)
	if err != nil {
		return nil, err
	}
	if unknown == "" {
		return []byte(RenderServer(c)), nil
	}
	return MergeServer(raw, c)
}

// ComposeClient renders an existing client config. replaceProxies selects
// whether cfg.Proxies replaces the proxy list (port edits) or the original
// list is kept byte-for-byte in the parsed tree (connection-only edits to a
// config with unknown proxy keys).
func ComposeClient(raw []byte, c *ClientConfig, replaceProxies bool) ([]byte, error) {
	// Range templates cannot be decoded as TOML, so they take a dedicated
	// path: merge any extra top-level keys, then append the canonical range
	// blocks. This keeps the editor structural (never raw-only).
	if c.RangeTemplate {
		return ComposeRangeClient(raw, c)
	}
	_, unknown, err := Classify(raw, KindClient)
	if err != nil {
		return nil, err
	}
	if unknown == "" {
		return []byte(RenderClient(c)), nil
	}
	return MergeClient(raw, c, replaceProxies)
}

// ComposeRangeClient merges a range-template config. Unknown keys outside the
// template block survive; the proxy block itself is always re-rendered from
// the model so port edits remain deterministic.
func ComposeRangeClient(raw []byte, c *ClientConfig) ([]byte, error) {
	stripped, _, ok := stripRangeBlocks(raw)
	if !ok {
		// New file (or a plain config switched to template mode).
		return []byte(RenderClient(c)), nil
	}
	var m map[string]any
	if err := toml.Unmarshal(stripped, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	unknown, _ := classifyClient(m)
	if unknown == "" {
		return []byte(RenderClient(c)), nil
	}
	applyClientTree(m, c, true)
	delete(m, "proxies")
	var b strings.Builder
	renderClientProxies(&b, c)
	out, err := toml.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(append(out, '\n'), []byte(b.String())...), nil
}

// MergeServer applies the managed server fields to raw's parsed TOML tree.
func MergeServer(raw []byte, c *ServerConfig) ([]byte, error) {
	m, err := decodeTree(raw)
	if err != nil {
		return nil, err
	}
	m["bindAddr"] = c.BindAddr
	m["bindPort"] = c.BindPort
	if c.ProxyBindAddr != "" {
		m["proxyBindAddr"] = c.ProxyBindAddr
	} else {
		delete(m, "proxyBindAddr")
	}
	if c.QUICBindPort > 0 {
		m["quicBindPort"] = c.QUICBindPort
	} else {
		delete(m, "quicBindPort")
	}
	if c.KCPBindPort > 0 {
		m["kcpBindPort"] = c.KCPBindPort
	} else {
		delete(m, "kcpBindPort")
	}

	t := ensureTable(m, "transport")
	if c.Transport.HeartbeatTimeout > 0 {
		t["heartbeatTimeout"] = c.Transport.HeartbeatTimeout
	}
	if c.Transport.MaxPoolCount > 0 {
		t["maxPoolCount"] = c.Transport.MaxPoolCount
	}
	t["tcpMux"] = c.Transport.TCPMux
	if c.Transport.TCPMuxKeepaliveInterval > 0 {
		t["tcpMuxKeepaliveInterval"] = c.Transport.TCPMuxKeepaliveInterval
	}
	if c.Transport.TCPKeepalive > 0 {
		t["tcpKeepalive"] = c.Transport.TCPKeepalive
	}
	if c.Transport.QUIC != (QUIC{}) {
		q := ensureTable(t, "quic")
		q["keepalivePeriod"] = c.Transport.QUIC.KeepalivePeriod
		q["maxIdleTimeout"] = c.Transport.QUIC.MaxIdleTimeout
		q["maxIncomingStreams"] = c.Transport.QUIC.MaxIncomingStreams
	}

	a := ensureTable(m, "auth")
	if c.Auth.Method != "" {
		a["method"] = c.Auth.Method
	}
	if c.Auth.Token != "" {
		a["token"] = c.Auth.Token
	}
	mergeWebServer(m, c.WebServer)
	return toml.Marshal(m)
}

// MergeClient applies the managed client fields to raw's parsed TOML tree.
func MergeClient(raw []byte, c *ClientConfig, replaceProxies bool) ([]byte, error) {
	m, err := decodeTree(raw)
	if err != nil {
		// Converting a range template to plain proxies: merge the non-template
		// remainder so extra keys survive the layout change.
		if stripped, _, ok := stripRangeBlocks(raw); ok {
			m, err = decodeTree(stripped)
		}
	}
	if err != nil {
		return nil, err
	}
	applyClientTree(m, c, replaceProxies)
	return toml.Marshal(m)
}

// applyClientTree writes every managed client field into an already-decoded
// TOML tree, preserving unknown tables (log, plugins, extra proxy keys, …).
func applyClientTree(m map[string]any, c *ClientConfig, replaceProxies bool) {
	m["serverAddr"] = c.ServerAddr
	m["serverPort"] = c.ServerPort
	m["loginFailExit"] = c.LoginFailExit

	a := ensureTable(m, "auth")
	if c.Auth.Method != "" {
		a["method"] = c.Auth.Method
	}
	if c.Auth.Token != "" {
		a["token"] = c.Auth.Token
	}

	t := ensureTable(m, "transport")
	if c.Transport.Protocol != "" {
		t["protocol"] = c.Transport.Protocol
	}
	t["tcpMux"] = c.Transport.TCPMux
	if c.Transport.TCPMuxKeepaliveInterval > 0 {
		t["tcpMuxKeepaliveInterval"] = c.Transport.TCPMuxKeepaliveInterval
	}
	if c.Transport.DialServerTimeout > 0 {
		t["dialServerTimeout"] = c.Transport.DialServerTimeout
	}
	if c.Transport.DialServerKeepalive > 0 {
		t["dialServerKeepalive"] = c.Transport.DialServerKeepalive
	}
	if c.Transport.PoolCount > 0 {
		t["poolCount"] = c.Transport.PoolCount
	}
	if c.Transport.HeartbeatInterval > 0 {
		t["heartbeatInterval"] = c.Transport.HeartbeatInterval
	}
	if c.Transport.HeartbeatTimeout > 0 {
		t["heartbeatTimeout"] = c.Transport.HeartbeatTimeout
	}
	tls := ensureTable(t, "tls")
	tls["enable"] = c.Transport.TLS.Enable
	if c.Transport.QUIC != (QUIC{}) {
		q := ensureTable(t, "quic")
		q["keepalivePeriod"] = c.Transport.QUIC.KeepalivePeriod
		q["maxIdleTimeout"] = c.Transport.QUIC.MaxIdleTimeout
		q["maxIncomingStreams"] = c.Transport.QUIC.MaxIncomingStreams
	}

	mergeWebServer(m, c.WebServer)
	if replaceProxies {
		m["proxies"] = proxiesToTree(c.Proxies, m["proxies"])
	}
}

func decodeTree(raw []byte) (map[string]any, error) {
	var m map[string]any
	if err := toml.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func ensureTable(m map[string]any, key string) map[string]any {
	if sub, ok := m[key].(map[string]any); ok {
		return sub
	}
	sub := map[string]any{}
	m[key] = sub
	return sub
}

func mergeWebServer(m map[string]any, w WebServer) {
	if !w.Enabled() {
		return // no webServer in the model: leave any existing raw block alone
	}
	wm := ensureTable(m, "webServer")
	wm["addr"] = w.Addr
	wm["port"] = w.Port
	wm["user"] = w.User
	wm["password"] = w.Password
}

// proxiesToTree rebuilds the [[proxies]] array while carrying forward any
// extra keys already present on a proxy with the same name (subdomain,
// annotations, healthCheck, …).
func proxiesToTree(proxies []Proxy, original any) []any {
	existing := map[string]map[string]any{}
	if arr, ok := original.([]any); ok {
		for _, e := range arr {
			pm, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if name, ok := pm["name"].(string); ok {
				existing[name] = pm
			}
		}
	}
	out := make([]any, 0, len(proxies))
	for _, p := range proxies {
		pm := existing[p.Name]
		if pm == nil {
			pm = map[string]any{}
		}
		pm["name"] = p.Name
		pm["type"] = p.Type
		pm["localIP"] = p.LocalIP
		pm["localPort"] = p.LocalPort
		pm["remotePort"] = p.RemotePort
		pt := ensureTable(pm, "transport")
		pt["useEncryption"] = p.Transport.UseEncryption
		pt["useCompression"] = p.Transport.UseCompression
		out = append(out, pm)
	}
	return out
}
