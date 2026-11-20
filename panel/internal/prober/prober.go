// Package prober is the panel's latency engine: it derives probe targets
// from the suite's own state files (GRE .env peer IPs, frpc control
// channels), samples them on a fixed interval and keeps a bounded history
// per target. The panel's SSE stream subscribes to its broadcast.
//
// Probing mechanics are injectable (ProbeFunc) — production uses the ping
// binary via svc.Runner and a TCP dial; tests use canned functions.
package prober

import (
	"context"
	"sync"
	"time"
)

// Target kinds.
const (
	KindICMP        = "icmp"         // ping a public IP
	KindICMPTunnel  = "icmp-tunnel"  // ping the private peer through the GRE iface
	KindTCP         = "tcp"          // TCP connect RTT (frp control channel)
)

// DefaultInterval is the probe cadence (5 s per docs/ARCHITECTURE.md §9).
const DefaultInterval = 5 * time.Second

// ringCap bounds samples kept per target (3600 = 5 h at 5 s cadence).
const ringCap = 3600

// lossWindow is the rolling window loss% is computed over.
const lossWindow = 60

// Target is one probe destination, derived from a suite config file.
type Target struct {
	ID    string `json:"id"`    // stable key, e.g. "gre-gt11-private"
	Kind  string `json:"kind"`  // icmp | icmp-tunnel | tcp
	Host  string `json:"host"`  // IP for icmp*, host:port for tcp
	Iface string `json:"iface,omitempty"`
	Label string `json:"label,omitempty"` // human hint, e.g. the source unit
}

// Sample is one probe result.
type Sample struct {
	TS    time.Time
	OK    bool
	RTTms float64
}

// ProbeFunc probes one target, returning the RTT in milliseconds.
type ProbeFunc func(Target) (float64, error)

// TargetStatus is the summarized state of a target.
type TargetStatus struct {
	Target
	OK      bool      `json:"ok"`
	RTTms   float64   `json:"rtt_ms"`
	LossPct float64   `json:"loss_pct"`
	Samples int       `json:"samples"`
	LastTS  time.Time `json:"-"`
}

// Snapshot is a whole-prober reading.
type Snapshot struct {
	TS      time.Time      `json:"-"`
	Targets []TargetStatus `json:"targets"`
}

// Prober runs the probe loop. All state is mutex-guarded; Tick is safe to
// call directly (tests) while Start's loop runs.
type Prober struct {
	mu       sync.Mutex
	targets  []Target
	hist     map[string][]Sample
	notify   chan struct{}
	ping     ProbeFunc
	dial     ProbeFunc
	interval time.Duration
	now      func() time.Time
	refresh  func() []Target
}

// New builds a prober. refresh re-derives targets from disk on every tick;
// ping/dial are the probe mechanics; now is the injectable clock.
func New(interval time.Duration, ping, dial ProbeFunc, now func() time.Time, refresh func() []Target) *Prober {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if now == nil {
		now = time.Now
	}
	return &Prober{
		hist:     map[string][]Sample{},
		notify:   make(chan struct{}),
		ping:     ping,
		dial:     dial,
		interval: interval,
		now:      now,
		refresh:  refresh,
	}
}

// Tick refreshes targets from disk, probes each once, records the samples
// and wakes every subscriber.
func (p *Prober) Tick() {
	if p.refresh != nil {
		if targets := p.refresh(); targets != nil {
			p.setTargets(targets)
		}
	}
	now := p.now()
	for _, t := range p.Snapshot().Targets {
		var (
			rtt float64
			err error
		)
		switch t.Kind {
		case KindICMP, KindICMPTunnel:
			if p.ping != nil {
				rtt, err = p.ping(t.Target)
			}
		case KindTCP:
			if p.dial != nil {
				rtt, err = p.dial(t.Target)
			}
		default:
			continue
		}
		p.mu.Lock()
		s := Sample{TS: now, OK: err == nil && rtt >= 0, RTTms: rtt}
		if err != nil {
			s.RTTms = 0
		}
		p.hist[t.ID] = appendSample(p.hist[t.ID], s)
		p.mu.Unlock()
	}
	p.mu.Lock()
	close(p.notify)
	p.notify = make(chan struct{})
	p.mu.Unlock()
}

func appendSample(hist []Sample, s Sample) []Sample {
	hist = append(hist, s)
	if len(hist) > ringCap {
		hist = hist[len(hist)-ringCap:]
	}
	return hist
}

// setTargets replaces the target list; history for departed targets is
// dropped so the ring buffers stay bounded.
func (p *Prober) setTargets(targets []Target) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = targets
	keep := map[string]bool{}
	for _, t := range targets {
		keep[t.ID] = true
	}
	for id := range p.hist {
		if !keep[id] {
			delete(p.hist, id)
		}
	}
}

// Targets returns the current derived target list.
func (p *Prober) Targets() []Target {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Target(nil), p.targets...)
}

// Subscribe returns a channel closed on the next tick (broadcast fan-out).
// Call again after every wake to re-arm.
func (p *Prober) Subscribe() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.notify
}

// Interval reports the configured probe cadence.
func (p *Prober) Interval() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.interval
}

// Snapshot summarizes every target: latest sample, loss% over the rolling
// window and the history size.
func (p *Prober) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	snap := Snapshot{TS: p.now(), Targets: []TargetStatus{}}
	for _, t := range p.targets {
		hist := p.hist[t.ID]
		st := TargetStatus{Target: t, Samples: len(hist)}
		if len(hist) > 0 {
			last := hist[len(hist)-1]
			st.OK = last.OK
			st.RTTms = last.RTTms
			st.LastTS = last.TS
		}
		window := hist
		if len(window) > lossWindow {
			window = window[len(window)-lossWindow:]
		}
		if len(window) > 0 {
			failed := 0
			for _, s := range window {
				if !s.OK {
					failed++
				}
			}
			st.LossPct = float64(failed) * 100 / float64(len(window))
		}
		snap.Targets = append(snap.Targets, st)
	}
	return snap
}

// Start runs the tick loop until ctx is canceled. Called once from the
// panel's serve lifecycle; tests usually call Tick directly instead.
func (p *Prober) Start(ctx context.Context) {
	ticker := time.NewTicker(p.Interval())
	defer ticker.Stop()
	p.Tick() // populate history immediately
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Tick()
		}
	}
}
