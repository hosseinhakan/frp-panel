// Package stats scrapes the metrics endpoint every FRP instance exposes on
// its loopback webServer block (the same endpoint that powers FRP's own
// dashboard) and keeps a bounded per-instance history.
//
// Response shapes are version-tolerant:
//
//   - frpc: GET /api/status → {"tcp":[{name,type,status,err,local_addr,
//     plugin,remote_addr},…], "udp":[…], …}
//   - frps: GET /api/serverinfo → {version, totalTrafficIn, totalTrafficOut,
//     curConns, clientCounts, proxyTypeCount:{…}}
//     GET /api/proxy/<type> → {proxies:[{name, todayTrafficIn,
//     todayTrafficOut, curConns, status, …},…]}
//
// Both camelCase (current FRP) and snake_case (older FRP) keys are accepted.
package stats

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/svc"
)

// FetchFunc retrieves one metrics URL with basic auth. Injectable for tests.
// code is the HTTP status; body is only valid when err == nil.
type FetchFunc func(url, user, password string) (body []byte, code int, err error)

// HTTPFetch is the production FetchFunc.
func HTTPFetch(url, user, password string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ProxyStat is one proxy row from an instance's metrics.
type ProxyStat struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	Err             string `json:"err,omitempty"`
	LocalAddr       string `json:"local_addr,omitempty"`
	RemoteAddr      string `json:"remote_addr,omitempty"`
	CurConns        int64  `json:"cur_conns"`
	TodayTrafficIn  uint64 `json:"today_traffic_in"`
	TodayTrafficOut uint64 `json:"today_traffic_out"`
}

// InstanceStat is the scraped state of one frps/frpc instance.
type InstanceStat struct {
	Kind             string           `json:"kind"` // server | client
	Name             string           `json:"name"`
	Port             int              `json:"port"` // webServer port scraped
	Up               bool             `json:"up"`
	Error            string           `json:"error,omitempty"`
	Version          string           `json:"version,omitempty"`
	CurConns         int64            `json:"cur_conns"`
	ClientCounts     int64            `json:"client_counts"`
	TotalTrafficIn   uint64           `json:"total_traffic_in"`
	TotalTrafficOut  uint64           `json:"total_traffic_out"`
	ProxyTypeCount   map[string]int64 `json:"proxy_type_count,omitempty"`
	Proxies          []ProxyStat      `json:"proxies"`
}

// HistSample is one point of the rolling per-instance history.
type HistSample struct {
	TS    time.Time `json:"ts"`
	In    uint64    `json:"in"`
	Out   uint64    `json:"out"`
	Conns int64     `json:"conns"`
}

// History limits: one sample per minute, 24 h retained (docs §9).
const (
	histMinSpacing = time.Minute
	histKeep       = 24 * time.Hour
)

// proxyTypes are the frps proxy endpoints probed in addition to whatever
// proxyTypeCount reports.
var proxyTypes = []string{"tcp", "udp"}

// Scraper reads instance metrics and keeps history.
type Scraper struct {
	mu   sync.Mutex
	fetch FetchFunc
	hist map[string][]HistSample
	now  func() time.Time
}

// New builds a Scraper (fetch and now injectable; nil means HTTPFetch/time.Now).
func New(fetch FetchFunc, now func() time.Time) *Scraper {
	if fetch == nil {
		fetch = HTTPFetch
	}
	if now == nil {
		now = time.Now
	}
	return &Scraper{fetch: fetch, hist: map[string][]HistSample{}, now: now}
}

// scrapeJob is one instance to fetch.
type scrapeJob struct {
	kind string
	name string
	url  string
	user string
	pass string
	port int
}

// Collect scrapes every instance whose config has a webServer block.
// Instances are scraped in parallel (each fetch has its own 3 s timeout);
// the result is sorted by kind then name. Up instances append a history
// sample (at most one per minute; entries older than 24 h are trimmed).
func (s *Scraper) Collect(paths svc.Paths) []InstanceStat {
	jobs := []scrapeJob{}

	if names, err := frpconf.ListConfigs(paths.ServerDir); err == nil {
		for _, n := range names {
			c, err := frpconf.ReadServer(filepath.Join(paths.ServerDir, n+".toml"))
			if err != nil || !c.WebServer.Enabled() {
				continue
			}
			jobs = append(jobs, s.job("server", n, c.WebServer))
		}
	}
	if names, err := frpconf.ListConfigs(paths.ClientDir); err == nil {
		for _, n := range names {
			c, err := frpconf.ReadClient(filepath.Join(paths.ClientDir, n+".toml"))
			if err != nil || !c.WebServer.Enabled() {
				continue
			}
			jobs = append(jobs, s.job("client", n, c.WebServer))
		}
	}

	out := make([]InstanceStat, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j scrapeJob) {
			defer wg.Done()
			if j.kind == "server" {
				out[i] = s.scrapeServer(j.url, j.user, j.pass)
			} else {
				out[i] = s.scrapeClient(j.url, j.user, j.pass)
			}
			out[i].Kind = j.kind
			out[i].Name = j.name
			out[i].Port = j.port
		}(i, j)
	}
	wg.Wait()

	// Sorted, deterministic order.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Kind+out[j].Name < out[j-1].Kind+out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}

	now := s.now()
	s.mu.Lock()
	for _, st := range out {
		if !st.Up {
			continue
		}
		key := st.Kind + "/" + st.Name
		h := s.hist[key]
		if n := len(h); n > 0 && now.Sub(h[n-1].TS) < histMinSpacing {
			continue // at most one sample per minute
		}
		h = append(h, HistSample{TS: now, In: st.TotalTrafficIn, Out: st.TotalTrafficOut, Conns: st.CurConns})
		cut := now.Add(-histKeep)
		drop := 0
		for drop < len(h) && h[drop].TS.Before(cut) {
			drop++
		}
		if drop > 0 {
			h = h[drop:]
		}
		s.hist[key] = h
	}
	s.mu.Unlock()
	return out
}

// job builds the base URL for an instance's webServer.
func (s *Scraper) job(kind, name string, w frpconf.WebServer) scrapeJob {
	addr := w.Addr
	switch addr {
	case "", "0.0.0.0":
		addr = "127.0.0.1"
	case "::", "[::]":
		addr = "::1"
	}
	// net.JoinHostPort brackets IPv6 for us.
	return scrapeJob{kind, name,
		fmt.Sprintf("http://%s", net.JoinHostPort(addr, fmt.Sprint(w.Port))),
		w.User, w.Password, w.Port}
}

// scrapeClient reads GET /api/status (proxy status map).
func (s *Scraper) scrapeClient(baseURL, user, pass string) InstanceStat {
	st := InstanceStat{Proxies: []ProxyStat{}}
	body, code, err := s.fetch(baseURL+"/api/status", user, pass)
	if err != nil || code != http.StatusOK {
		st.Error = fetchErr(code, err)
		return st
	}
	proxies, ok := ParseStatusMap(body)
	if !ok {
		st.Error = "unrecognized /api/status response"
		return st
	}
	st.Up = true
	for _, p := range proxies {
		st.Proxies = append(st.Proxies, p)
		st.CurConns += p.CurConns
	}
	return st
}

// scrapeServer reads /api/serverinfo (totals) then /api/proxy/<type> rows.
func (s *Scraper) scrapeServer(baseURL, user, pass string) InstanceStat {
	st := InstanceStat{Proxies: []ProxyStat{}}

	body, code, err := s.fetch(baseURL+"/api/serverinfo", user, pass)
	if err != nil || code != http.StatusOK {
		// Very old frps exposed everything under /api/status instead.
		if code == http.StatusNotFound {
			if alt, altCode, altErr := s.fetch(baseURL+"/api/status", user, pass); altErr == nil && altCode == http.StatusOK {
				if info, ok := ParseServerInfo(alt); ok {
					applyServerInfo(&st, info)
					st.Up = true
					return st
				}
			}
		}
		st.Error = fetchErr(code, err)
		return st
	}
	info, ok := ParseServerInfo(body)
	if !ok {
		st.Error = "unrecognized /api/serverinfo response"
		return st
	}
	applyServerInfo(&st, info)
	st.Up = true

	types := map[string]bool{}
	for _, t := range proxyTypes {
		types[t] = true
	}
	for t := range st.ProxyTypeCount {
		types[strings.ToLower(t)] = true
	}
	for t := range types {
		pb, code, err := s.fetch(baseURL+"/api/proxy/"+t, user, pass)
		if err != nil || code != http.StatusOK {
			continue // absent type on this frps version
		}
		proxies, ok := ParseProxyList(pb)
		if !ok {
			continue
		}
		for _, p := range proxies {
			if p.Type == "" {
				p.Type = t
			}
			st.Proxies = append(st.Proxies, p)
		}
	}
	return st
}

func applyServerInfo(st *InstanceStat, info ServerInfo) {
	st.Version = info.Version
	st.CurConns = info.CurConns
	st.ClientCounts = info.ClientCounts
	st.TotalTrafficIn = info.TotalTrafficIn
	st.TotalTrafficOut = info.TotalTrafficOut
	st.ProxyTypeCount = info.ProxyTypeCount
}

func fetchErr(code int, err error) string {
	if err != nil {
		return err.Error()
	}
	if code == http.StatusNotFound {
		return "metrics endpoint not found (frp too old?)"
	}
	return fmt.Sprintf("metrics endpoint returned HTTP %d", code)
}

// History returns the retained samples for one instance (kind/name).
func (s *Scraper) History(kind, name string) []HistSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]HistSample(nil), s.hist[kind+"/"+name]...)
}

// ---- tolerant parsers ---------------------------------------------------------

// ServerInfo is the decoded /api/serverinfo payload (both key spellings).
type ServerInfo struct {
	Version         string
	CurConns        int64
	ClientCounts    int64
	TotalTrafficIn  uint64
	TotalTrafficOut uint64
	ProxyTypeCount  map[string]int64
}

// ParseServerInfo tolerantly decodes an frps serverinfo payload.
func ParseServerInfo(body []byte) (ServerInfo, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return ServerInfo{}, false
	}
	info := ServerInfo{
		Version:         strAny(m, "version"),
		CurConns:        intAny(m, "curConns", "cur_conns"),
		ClientCounts:    intAny(m, "clientCounts", "client_counts"),
		TotalTrafficIn:  uintAny(m, "totalTrafficIn", "total_traffic_in"),
		TotalTrafficOut: uintAny(m, "totalTrafficOut", "total_traffic_out"),
		ProxyTypeCount:  mapAny(m, "proxyTypeCount", "proxy_type_count"),
	}
	if info.Version == "" && info.TotalTrafficIn == 0 && info.TotalTrafficOut == 0 &&
		info.CurConns == 0 && info.ProxyTypeCount == nil {
		return ServerInfo{}, false // nothing recognized
	}
	return info, true
}

// ParseStatusMap decodes the frpc /api/status shape: {type: [proxy…]}.
func ParseStatusMap(body []byte) ([]ProxyStat, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, false
	}
	var out []ProxyStat
	any := false
	for typ, raw := range m {
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			continue // scalar keys (older servers mix totals in) are skipped
		}
		for _, e := range arr {
			p := parseProxyEntry(e)
			if p.Name == "" {
				continue
			}
			if p.Type == "" {
				p.Type = typ
			}
			out = append(out, p)
			any = true
		}
	}
	return out, any
}

// ParseProxyList decodes the frps /api/proxy/<type> shape: {proxies: […]}.
func ParseProxyList(body []byte) ([]ProxyStat, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, false
	}
	raw, ok := m["proxies"]
	if !ok {
		return nil, false
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, false
	}
	out := make([]ProxyStat, 0, len(arr))
	for _, e := range arr {
		p := parseProxyEntry(e)
		if p.Name == "" {
			continue
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

func parseProxyEntry(e map[string]json.RawMessage) ProxyStat {
	return ProxyStat{
		Name:            strAny(e, "name"),
		Type:            strAny(e, "type"),
		Status:          strAny(e, "status"),
		Err:             strAny(e, "err"),
		LocalAddr:       strAny(e, "local_addr", "localAddr"),
		RemoteAddr:      strAny(e, "remote_addr", "remoteAddr"),
		CurConns:        intAny(e, "curConns", "cur_conns"),
		TodayTrafficIn:  uintAny(e, "todayTrafficIn", "today_traffic_in"),
		TodayTrafficOut: uintAny(e, "todayTrafficOut", "today_traffic_out"),
	}
}

func strAny(m map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if raw, ok := m[k]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				return s
			}
		}
	}
	return ""
}

func intAny(m map[string]json.RawMessage, keys ...string) int64 {
	for _, k := range keys {
		if raw, ok := m[k]; ok {
			var v int64
			if err := json.Unmarshal(raw, &v); err == nil {
				return v
			}
		}
	}
	return 0
}

func uintAny(m map[string]json.RawMessage, keys ...string) uint64 {
	for _, k := range keys {
		if raw, ok := m[k]; ok {
			var v uint64
			if err := json.Unmarshal(raw, &v); err == nil {
				return v
			}
		}
	}
	return 0
}

func mapAny(m map[string]json.RawMessage, keys ...string) map[string]int64 {
	for _, k := range keys {
		if raw, ok := m[k]; ok {
			var v map[string]int64
			if err := json.Unmarshal(raw, &v); err == nil && len(v) > 0 {
				return v
			}
		}
	}
	return nil
}
