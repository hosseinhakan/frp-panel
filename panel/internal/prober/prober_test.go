package prober

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newTestProber(t *testing.T) (*Prober, *[]Target) {
	t.Helper()
	base := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	clock := base
	targets := []Target{
		{ID: "gre-gt11-public", Kind: KindICMP, Host: "5.6.7.8"},
		{ID: "gre-gt11-private", Kind: KindICMPTunnel, Host: "10.100.111.2", Iface: "gt11"},
		{ID: "frpc-c1-ctrl", Kind: KindTCP, Host: "10.100.111.2:7000"},
	}
	p := New(time.Second,
		func(t Target) (float64, error) {
			if t.Host == "10.100.111.2" {
				return 2.5, nil // private peer through the tunnel
			}
			return 12.5, nil
		},
		func(t Target) (float64, error) { return 3.75, nil },
		func() time.Time { return clock },
		func() []Target { return targets },
	)
	return p, &targets
}

func TestTickRecordsAndBroadcasts(t *testing.T) {
	p, _ := newTestProber(t)
	sub := p.Subscribe()

	p.Tick()

	snap := p.Snapshot()
	if len(snap.Targets) != 3 {
		t.Fatalf("snapshot has %d targets, want 3", len(snap.Targets))
	}
	byID := map[string]TargetStatus{}
	for _, st := range snap.Targets {
		byID[st.ID] = st
	}
	pub := byID["gre-gt11-public"]
	if !pub.OK || pub.RTTms != 12.5 || pub.LossPct != 0 || pub.Samples != 1 {
		t.Fatalf("public target = %+v", pub)
	}
	priv := byID["gre-gt11-private"]
	if priv.RTTms != 2.5 || priv.Iface != "gt11" {
		t.Fatalf("private target = %+v", priv)
	}
	ctrl := byID["frpc-c1-ctrl"]
	if !ctrl.OK || ctrl.RTTms != 3.75 {
		t.Fatalf("tcp target = %+v", ctrl)
	}

	select {
	case <-sub:
	default:
		t.Fatal("Tick must wake subscribers")
	}
	// The fired channel stays closed; a fresh subscribe arms the next tick.
	if _, ok := <-sub; ok {
		t.Fatal("broadcast channel must be closed")
	}
	sub2 := p.Subscribe()
	select {
	case <-sub2:
		t.Fatal("fresh subscription must not fire before the next tick")
	default:
	}
}

func TestLossRollingWindow(t *testing.T) {
	p, _ := newTestProber(t)
	// Make the public peer fail every other tick.
	odd := false
	p.ping = func(t Target) (float64, error) {
		if t.Host == "5.6.7.8" {
			odd = !odd
			if odd {
				return 0, errors.New("timeout")
			}
		}
		return 10, nil
	}
	p.Tick()
	p.Tick()
	p.Tick()
	p.Tick()
	snap := p.Snapshot()
	for _, st := range snap.Targets {
		if st.ID != "gre-gt11-public" {
			continue
		}
		if st.Samples != 4 {
			t.Fatalf("samples = %d, want 4", st.Samples)
		}
		if st.LossPct != 50 {
			t.Fatalf("loss = %v%%, want 50", st.LossPct)
		}
		// The failing pattern is fail/success/fail/success: the newest
		// sample succeeded and loss still reports the window honestly.
		if !st.OK {
			t.Fatalf("newest sample should be OK: %+v", st)
		}
	}
}

func TestRingCapAndTargetRefresh(t *testing.T) {
	p, targets := newTestProber(t)
	// Shrink the ring for the test via direct history stuffing.
	p.mu.Lock()
	fake := make([]Sample, ringCap+50)
	p.hist["gre-gt11-public"] = fake
	p.mu.Unlock()

	p.Tick()

	p.mu.Lock()
	if got := len(p.hist["gre-gt11-public"]); got != ringCap {
		t.Fatalf("ring grew to %d, want cap %d", got, ringCap)
	}
	p.mu.Unlock()

	// A tunnel deleted from disk disappears from targets and history.
	*targets = []Target{{ID: "frpc-c1-ctrl", Kind: KindTCP, Host: "x:1"}}
	p.Tick()
	for _, st := range p.Snapshot().Targets {
		if st.ID != "frpc-c1-ctrl" {
			t.Fatalf("stale target %q still present", st.ID)
		}
	}
	p.mu.Lock()
	if len(p.hist) != 1 {
		t.Fatalf("history for departed targets must be dropped (len=%d)", len(p.hist))
	}
	p.mu.Unlock()
}

func TestStartStopsOnCancel(t *testing.T) {
	p, _ := newTestProber(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Start(ctx); close(done) }()
	// Start's immediate Tick must have produced history.
	deadline := time.Now().Add(time.Second)
	for {
		if len(p.Snapshot().Targets) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Start did not tick")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not stop on cancel")
	}
}

func TestNilRefreshKeepsTargets(t *testing.T) {
	p := New(time.Second, nil, nil, nil, nil)
	p.Tick() // must not panic with a nil refresh/probe funcs
	if got := p.Snapshot(); len(got.Targets) != 0 {
		t.Fatalf("expected empty snapshot, got %+v", got)
	}
}
