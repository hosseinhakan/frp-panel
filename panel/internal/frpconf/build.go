package frpconf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Protocol selects the frps auxiliary transport (in addition to plain TCP).
type Protocol string

const (
	// ProtoQUIC enables quicBindPort on the frps side (the suite default).
	ProtoQUIC Protocol = "quic"
	// ProtoKCP enables kcpBindPort.
	ProtoKCP Protocol = "kcp"
	// ProtoNone leaves only plain TCP listening.
	ProtoNone Protocol = "none"
)

// Port ranges reserved for auto-allocated webServer blocks
// (FRP admin dashboards the panel scrapes for metrics).
const (
	ServerWebPortLo = 7500
	ServerWebPortHi = 7599
	ClientWebPortLo = 7400
	ClientWebPortHi = 7499
)

// ServerOptions collects the wizard inputs for a new frps instance.
type ServerOptions struct {
	BindAddr      string // default "::" (dual-stack, like the original script)
	BindPort      int    // default 7000
	ProxyBindAddr string // "" = derive from BindAddr (0.0.0.0 for a private/GRE IP)
	Protocol      Protocol
	TCPMux        bool
	Token         string // generated when empty
	WebAddr       string // default "127.0.0.1" when WebPort > 0
	WebPort       int    // 0 disables the webServer block
	WebUser       string // default "admin"
	WebPassword   string // generated when empty and WebPort > 0
}

// DefaultProxyBindAddr returns the proxyBindAddr frps needs for a given
// listen address. A wildcard (or empty) bindAddr already accepts the forwarded
// ports on every interface, so nothing is emitted. A specific address — most
// importantly the GRE tunnel IP used by the Iran entry node — makes frps bind
// the forwarded user ports to *that* address only, which is unreachable from
// the public internet. For those we return "0.0.0.0" so the control port stays
// private inside GRE while the forwarded ports listen publicly.
func DefaultProxyBindAddr(bindAddr string) string {
	switch strings.TrimSpace(bindAddr) {
	case "", "0.0.0.0", "::":
		return ""
	}
	return "0.0.0.0"
}

// NewServerConfig builds a ServerConfig with the suite's secure defaults.
func NewServerConfig(o ServerOptions) (*ServerConfig, error) {
	if o.BindPort <= 0 {
		o.BindPort = 7000
	}
	if o.BindAddr == "" {
		o.BindAddr = "::"
	}
	if o.ProxyBindAddr == "" {
		o.ProxyBindAddr = DefaultProxyBindAddr(o.BindAddr)
	}
	if o.Protocol == "" {
		o.Protocol = ProtoQUIC
	}

	c := &ServerConfig{BindAddr: o.BindAddr, BindPort: o.BindPort, ProxyBindAddr: o.ProxyBindAddr}
	switch o.Protocol {
	case ProtoQUIC:
		c.QUICBindPort = o.BindPort
	case ProtoKCP:
		c.KCPBindPort = o.BindPort
	case ProtoNone:
	default:
		return nil, errors.New("frpconf: unknown protocol " + string(o.Protocol))
	}

	c.Transport.QUIC = DefaultQUIC()
	// Stability-tuned for lossy long-haul links: a 45s heartbeat timeout with
	// frpc's 15s interval detects dead peers fast without flapping.
	c.Transport.HeartbeatTimeout = 45
	c.Transport.MaxPoolCount = 65535
	c.Transport.TCPMux = o.TCPMux
	c.Transport.TCPMuxKeepaliveInterval = 10
	c.Transport.TCPKeepalive = 30

	c.Auth.Method = "token"
	if o.Token == "" {
		tok, err := RandomToken()
		if err != nil {
			return nil, err
		}
		o.Token = tok
	}
	c.Auth.Token = o.Token

	if o.WebPort > 0 {
		if o.WebAddr == "" {
			o.WebAddr = "127.0.0.1"
		}
		if o.WebUser == "" {
			o.WebUser = "admin"
		}
		if o.WebPassword == "" {
			pw, err := RandomPassword()
			if err != nil {
				return nil, err
			}
			o.WebPassword = pw
		}
		c.WebServer = WebServer{Addr: o.WebAddr, Port: o.WebPort, User: o.WebUser, Password: o.WebPassword}
	}
	return c, nil
}

// ClientOptions collects the wizard inputs for a new frpc instance.
type ClientOptions struct {
	ServerAddr     string
	ServerPort     int    // default 7000
	Token          string // required (must match the frps token)
	Protocol       string // "tcp" | "websocket" | "quic" | "kcp" (default tcp)
	TCPMux         bool
	UseTLS         bool  // default false (mikeesierrah profile: TLS off for speed)
	UseEncryption  *bool // per-proxy encryption; nil = false (profile default)
	UseCompression bool  // default false (saves RAM)
	Ports          []PortSpec
	Proto          ProtoToggle // default ProtoTCPAndUDP (dual TCP+UDP toggle)
	LocalIP        string      // default "127.0.0.1"
	WebAddr        string
	WebPort        int
	WebUser        string
	WebPassword    string
	// PlainProxies opts out of the compact parseNumberRangePair template and
	// emits one [[proxies]] block per port. The suite default is the template
	// (the proven mikeesierrah profile), so zero-value callers get it.
	PlainProxies bool
}

// NewClientConfig builds a ClientConfig with the mikeesierrah profile:
// TLS off, per-proxy encryption off, compression off, paired tcp/udp proxies
// rendered through parseNumberRangePair so ranges stay compact.
func NewClientConfig(o ClientOptions) (*ClientConfig, error) {
	if o.ServerAddr == "" {
		return nil, errors.New("frpconf: client requires serverAddr")
	}
	if o.ServerPort <= 0 {
		o.ServerPort = 7000
	}
	if o.Token == "" {
		return nil, errors.New("frpconf: client token must match the server token (refusing empty)")
	}
	if o.Protocol == "" {
		o.Protocol = "tcp"
	}
	if o.LocalIP == "" {
		o.LocalIP = "127.0.0.1"
	}
	if o.Proto == ProtoUnset {
		o.Proto = ProtoTCPAndUDP
	}

	c := &ClientConfig{
		ServerAddr:    o.ServerAddr,
		ServerPort:    o.ServerPort,
		LoginFailExit: false,
	}
	c.Auth.Method = "token"
	c.Auth.Token = o.Token

	t := &c.Transport
	t.Protocol = o.Protocol
	t.TCPMux = o.TCPMux
	t.TCPMuxKeepaliveInterval = 10
	t.DialServerTimeout = 10
	// Stability-tuned for high-loss Iran↔Foreign GRE links: a smaller pool
	// avoids bursty SYN floods on reconnect, and the 15s/45s heartbeat pair
	// fails over quickly without flapping.
	t.DialServerKeepalive = 30
	t.PoolCount = 10
	t.HeartbeatInterval = 15
	t.HeartbeatTimeout = 45
	t.TLS.Enable = o.UseTLS
	t.QUIC = DefaultQUIC()

	if o.WebPort > 0 {
		if o.WebAddr == "" {
			o.WebAddr = "127.0.0.1"
		}
		if o.WebUser == "" {
			o.WebUser = "admin"
		}
		if o.WebPassword == "" {
			pw, err := RandomPassword()
			if err != nil {
				return nil, err
			}
			o.WebPassword = pw
		}
		c.WebServer = WebServer{Addr: o.WebAddr, Port: o.WebPort, User: o.WebUser, Password: o.WebPassword}
	}

	encrypt := false
	if o.UseEncryption != nil {
		encrypt = *o.UseEncryption
	}
	c.Proxies = BuildProxies(o.Ports, o.Proto, o.LocalIP, encrypt, o.UseCompression)
	if !o.PlainProxies && len(o.Ports) > 0 {
		c.RangeTemplate = true
		c.RangeLocal = FormatPortSpecs(o.Ports)
		c.RangeRemote = c.RangeLocal
	}
	return c, nil
}

// AllocatePort returns the first free port in [lo, hi] given the used set.
func AllocatePort(used map[int]bool, lo, hi int) (int, bool) {
	for p := lo; p <= hi; p++ {
		if !used[p] {
			return p, true
		}
	}
	return 0, false
}

func writeFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
