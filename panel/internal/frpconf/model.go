package frpconf

// Kind identifies which FRP binary a config targets.
type Kind uint8

const (
	// KindServer targets frps (config files under /root/frp/server/).
	KindServer Kind = iota
	// KindClient targets frpc (config files under /root/frp/client/).
	KindClient
)

func (k Kind) String() string {
	if k == KindClient {
		return "client"
	}
	return "server"
}

// WebServer mirrors frp's webServer block (admin dashboard + /api/status metrics
// endpoint, which the panel scrapes for per-proxy traffic stats).
type WebServer struct {
	Addr     string `toml:"addr"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
}

// Enabled reports whether a webServer block should be emitted. The panel only
// binds these to loopback; they exist for metrics, not for remote access.
func (w WebServer) Enabled() bool { return w.Port > 0 && w.Addr != "" && w.User != "" }

// QUIC mirrors frp's transport.quic tuning block.
type QUIC struct {
	KeepalivePeriod    int `toml:"keepalivePeriod"`
	MaxIdleTimeout     int `toml:"maxIdleTimeout"`
	MaxIncomingStreams int `toml:"maxIncomingStreams"`
}

// DefaultQUIC holds the tuning values the suite writes by default
// (identical to the original script's choices).
func DefaultQUIC() QUIC {
	return QUIC{KeepalivePeriod: 10, MaxIdleTimeout: 30, MaxIncomingStreams: 100000}
}

// IsZero reports whether no QUIC tuning was decoded from the file.
func (q QUIC) IsZero() bool { return q == QUIC{} }

// ServerConfig is the managed subset of an frps TOML config.
//
// Only fields the suite itself writes are modeled; files containing anything
// else are classified StyleAdvanced/StyleTemplate and edited as raw text
// (see Classify and docs/ARCHITECTURE.md §4.3).
type ServerConfig struct {
	BindAddr string `toml:"bindAddr"`
	BindPort int    `toml:"bindPort"`
	// ProxyBindAddr is where frps binds the *forwarded user ports*. When frps
	// listens on a private/GRE address the control port must stay private, but
	// the forwarded ports still have to be reachable from the public internet —
	// without this FRP binds them to the GRE IP and they are unreachable.
	// Empty means "same as bindAddr" (frp's own default).
	ProxyBindAddr string `toml:"proxyBindAddr"` // "" = unset
	QUICBindPort  int    `toml:"quicBindPort"`  // 0 = unset
	KCPBindPort   int    `toml:"kcpBindPort"`   // 0 = unset

	Transport struct {
		QUIC                    QUIC `toml:"quic"`
		HeartbeatTimeout        int  `toml:"heartbeatTimeout"`
		MaxPoolCount            int  `toml:"maxPoolCount"`
		TCPMux                  bool `toml:"tcpMux"`
		TCPMuxKeepaliveInterval int  `toml:"tcpMuxKeepaliveInterval"`
		TCPKeepalive            int  `toml:"tcpKeepalive"`
	} `toml:"transport"`

	Auth struct {
		Method string `toml:"method"`
		Token  string `toml:"token"`
	} `toml:"auth"`

	WebServer WebServer `toml:"webServer"`
}

// ClientConfig is the managed subset of an frpc TOML config.
type ClientConfig struct {
	ServerAddr    string `toml:"serverAddr"`
	ServerPort    int    `toml:"serverPort"`
	LoginFailExit bool   `toml:"loginFailExit"`

	Auth struct {
		Method string `toml:"method"`
		Token  string `toml:"token"`
	} `toml:"auth"`

	Transport struct {
		Protocol                string `toml:"protocol"`
		TCPMux                  bool   `toml:"tcpMux"`
		TCPMuxKeepaliveInterval int    `toml:"tcpMuxKeepaliveInterval"`
		DialServerTimeout       int    `toml:"dialServerTimeout"`
		DialServerKeepalive     int    `toml:"dialServerKeepalive"`
		PoolCount               int    `toml:"poolCount"`
		HeartbeatInterval       int    `toml:"heartbeatInterval"`
		HeartbeatTimeout        int    `toml:"heartbeatTimeout"`
		TLS                     struct {
			Enable bool `toml:"enable"`
		} `toml:"tls"`
		QUIC QUIC `toml:"quic"`
	} `toml:"transport"`

	WebServer WebServer `toml:"webServer"`
	Proxies   []Proxy   `toml:"proxies"`

	// RangeTemplate records that this client config is written with FRP's
	// Go-template port expansion:
	//
	//	{{- range $_, $v := parseNumberRangePair "22,6000-6006" "22,6000-6006" }}
	//
	// Proxies always holds the expanded view so the panel can show and edit
	// every forwarded port; RangeLocal/RangeRemote preserve the exact input
	// lists so re-rendering keeps the compact, proven mikeesierrah layout.
	RangeTemplate bool   `toml:"-"`
	RangeLocal    string `toml:"-"`
	RangeRemote   string `toml:"-"`
}

// Proxy is one [[proxies]] block in a client config.
type Proxy struct {
	Name       string `toml:"name"`
	Type       string `toml:"type"` // "tcp" | "udp"
	LocalIP    string `toml:"localIP"`
	LocalPort  int    `toml:"localPort"`
	RemotePort int    `toml:"remotePort"`

	Transport struct {
		UseEncryption  bool `toml:"useEncryption"`
		UseCompression bool `toml:"useCompression"`
	} `toml:"transport"`
}
