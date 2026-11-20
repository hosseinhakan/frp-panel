// Monitoring API: latency prober (snapshot + SSE), journal log streaming
// (SSE over journalctl, suite units only) and the FRP webServer stats
// scraper. All handlers are session-guarded; the probe/journal mechanics
// run through svc.Runner so tests drive them with canned fakes.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/frp-suite/panel/internal/frpconf"
	"github.com/frp-suite/panel/internal/gre"
	"github.com/frp-suite/panel/internal/journal"
	"github.com/frp-suite/panel/internal/prober"
	"github.com/frp-suite/panel/internal/svc"
)

// probeTargets derives the panel's probe set from the suite's own state
// files: every GRE tunnel contributes a public-peer ICMP target and a
// private-peer-through-the-tunnel target, every frpc instance a TCP RTT
// target for its control channel.
func (s *Server) probeTargets() []prober.Target {
	targets := []prober.Target{}
	seen := map[string]bool{}
	add := func(t prober.Target) {
		if !seen[t.ID] {
			seen[t.ID] = true
			targets = append(targets, t)
		}
	}

	if tunnels, _, err := gre.List(s.paths.GREDir); err == nil {
		for _, t := range tunnels {
			if t.RemotePublicIP != "" {
				add(prober.Target{
					ID: "gre-" + t.Name + "-public", Kind: prober.KindICMP,
					Host: t.RemotePublicIP, Label: "GRE peer (public) " + t.Iface,
				})
			}
			if peer := strings.SplitN(t.RemotePrivateIP, "/", 2)[0]; peer != "" && t.Iface != "" {
				add(prober.Target{
					ID: "gre-" + t.Name + "-private", Kind: prober.KindICMPTunnel,
					Host: peer, Iface: t.Iface, Label: "GRE peer (tunnel) " + t.Iface,
				})
			}
		}
	}
	if names, err := frpconf.ListConfigs(s.paths.ClientDir); err == nil {
		for _, n := range names {
			c, err := frpconf.ReadClient(filepath.Join(s.paths.ClientDir, n+".toml"))
			if err != nil || c.ServerAddr == "" || c.ServerPort <= 0 {
				continue
			}
			add(prober.Target{
				ID: "frpc-" + n + "-ctrl", Kind: prober.KindTCP,
				Host: net.JoinHostPort(c.ServerAddr, strconv.Itoa(c.ServerPort)),
				Label: "frpc@" + n + " control channel",
			})
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets
}

// runnerPing probes an ICMP target with the ping binary (one packet).
func (s *Server) runnerPing(t prober.Target) (float64, error) {
	args := []string{"-c", "1", "-W", "2"}
	if t.Iface != "" {
		args = append(args, "-I", t.Iface)
	}
	args = append(args, t.Host)
	out, err := s.runner.Exec("ping", args...)
	if err != nil {
		return 0, err
	}
	return parsePingRTT(out)
}

// parsePingRTT extracts the `time=12.4 ms` value from a one-packet ping.
func parsePingRTT(out string) (float64, error) {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "time="); i >= 0 {
			fields := strings.Fields(line[i+len("time="):])
			if len(fields) >= 1 {
				if v, err := strconv.ParseFloat(strings.TrimSuffix(fields[0], "ms"), 64); err == nil {
					return v, nil
				}
			}
		}
	}
	return 0, errors.New("no rtt in ping output")
}

// tcpProbe measures a TCP connect RTT.
func tcpProbe(t prober.Target) (float64, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", t.Host, 3*time.Second)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return float64(time.Since(start).Microseconds()) / 1000.0, nil
}

// ---- latency snapshot + SSE ------------------------------------------------------

func (s *Server) handleLatency(w http.ResponseWriter, r *http.Request) {
	snap := s.prober.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"interval_seconds": int(s.prober.Interval().Seconds()),
		"targets":          latencyTargetsMap(snap),
	})
}

// latencyTargetsMap shapes the SSE payload per docs §5.5:
// {"id": {"ok":…, "rtt_ms":…, "loss_pct":…}} keyed by target ID.
func latencyTargetsMap(snap prober.Snapshot) map[string]any {
	m := map[string]any{}
	for _, st := range snap.Targets {
		m[st.ID] = map[string]any{
			"kind":      st.Kind,
			"host":      st.Host,
			"ok":        st.OK,
			"rtt_ms":    st.RTTms,
			"loss_pct":  st.LossPct,
			"samples":   st.Samples,
		}
	}
	return m
}

// handleLatencyStream is the live SSE feed: an immediate snapshot event,
// one event per probe tick and a 15 s heartbeat comment.
func (s *Server) handleLatencyStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	setSSEHeaders(w)
	w.WriteHeader(http.StatusOK)

	sseEvent(w, "snapshot", map[string]any{
		"ts":      s.now().Unix(),
		"targets": latencyTargetsMap(s.prober.Snapshot()),
	})
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	sub := s.prober.Subscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub:
			sub = s.prober.Subscribe() // re-arm for the next tick
			sseEvent(w, "sample", map[string]any{
				"ts":      s.now().Unix(),
				"targets": latencyTargetsMap(s.prober.Snapshot()),
			})
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
		}
		flusher.Flush()
	}
}

func setSSEHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
}

// sseEvent writes one `event:`/`data:` pair.
func sseEvent(w http.ResponseWriter, event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
}

// ---- log unit list + journal SSE ---------------------------------------------------

// handleLogUnits lists the units the log stream accepts (the same set the
// services API manages).
func (s *Server) handleLogUnits(w http.ResponseWriter, r *http.Request) {
	units := []string{}
	if names, err := frpconf.ListConfigs(s.paths.ServerDir); err == nil {
		for _, n := range names {
			units = append(units, "frps@"+n)
		}
	}
	if names, err := frpconf.ListConfigs(s.paths.ClientDir); err == nil {
		for _, n := range names {
			units = append(units, "frpc@"+n)
		}
	}
	if greNames, err := listEnvNames(s.paths.GREDir); err == nil {
		for _, n := range greNames {
			units = append(units, "gre-tunnel@"+n)
		}
	}
	units = append(units, suiteSingletons...)
	sort.Strings(units)
	writeJSON(w, http.StatusOK, map[string]any{"units": units})
}

// handleLogStream tails one suite unit's journal over SSE. The journalctl
// process lives exactly as long as the HTTP request: canceled context
// kills it, EOF ends the response (HTMX sse reconnects).
func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		writeErr(w, http.StatusBadRequest, "missing ?unit= parameter")
		return
	}
	family, instance, err := svc.ValidateUnit(unit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	// Template instances must resolve to an existing config, exactly like
	// the services action endpoint.
	if instance != "" {
		if _, err := os.Stat(s.unitConfigPath(family, instance)); err != nil {
			writeErr(w, http.StatusNotFound, "unit %q has no config file", unit)
			return
		}
	}

	lines := journal.DefaultLines
	if v := r.URL.Query().Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > journal.MaxLines {
			writeErr(w, http.StatusBadRequest, "lines must be 1..%d", journal.MaxLines)
			return
		}
		lines = n
	}
	since, err := journal.ParseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}

	rc, err := s.runner.ExecStream(r.Context(), "journalctl", journal.Args(unit, lines, since, true)...)
	if err != nil {
		writeErr(w, http.StatusConflict, "cannot stream %s: %v", unit, err)
		return
	}
	defer rc.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	setSSEHeaders(w)
	w.WriteHeader(http.StatusOK)
	sseEvent(w, "open", map[string]string{"unit": unit})
	flusher.Flush()

	// Reader goroutine → line channel; the handler loop multiplexes with
	// the heartbeat and client disconnect.
	lineCh := make(chan string, 64)
	go func() {
		defer close(lineCh)
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			select {
			case <-r.Context().Done():
				return
			case lineCh <- journal.Canonical(journal.StripANSI(sc.Text())):
			}
		}
	}()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	sent := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case line, ok := <-lineCh:
			if !ok {
				sseEvent(w, "eof", map[string]string{"unit": unit})
				flusher.Flush()
				return
			}
			sent++
			if sent > journal.RingLimit {
				// Client too slow / log too chatty — end the response;
				// a reconnect resumes with a fresh bounded tail.
				sseEvent(w, "overflow", map[string]any{"unit": unit, "limit": journal.RingLimit})
				flusher.Flush()
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", line)
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
		}
		flusher.Flush()
	}
}

// unitConfigPath maps a validated unit family/instance onto its config
// file. Shared by the services actions and the log stream.
func (s *Server) unitConfigPath(family, instance string) string {
	switch family {
	case "frps":
		return filepath.Join(s.paths.ServerDir, instance+".toml")
	case "frpc":
		return filepath.Join(s.paths.ClientDir, instance+".toml")
	case "gre-tunnel":
		return filepath.Join(s.paths.GREDir, instance+".env")
	}
	return ""
}

// ---- stats -------------------------------------------------------------------------

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	instance := r.URL.Query().Get("instance")
	stats := s.scraper.Collect(s.paths)
	history := map[string]any{}
	out := []any{}
	for _, st := range stats {
		if instance != "" && st.Name != instance {
			continue
		}
		out = append(out, st)
		if h := s.scraper.History(st.Kind, st.Name); len(h) > 0 {
			history[st.Name] = h
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": out, "history": history})
}

// StartMonitor launches the background probe loop (called from main's
// serve lifecycle; cancel ctx to stop).
func (s *Server) StartMonitor(ctx context.Context) {
	go s.prober.Start(ctx)
}
