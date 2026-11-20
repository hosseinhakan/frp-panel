package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/frp-suite/panel/internal/assets"
)

func TestWritePanelUnit(t *testing.T) {
	dir := t.TempDir()

	// Fresh directory: the unit is written and matches the canonical asset.
	path, changed, err := writePanelUnit(dir)
	if err != nil {
		t.Fatalf("writePanelUnit: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on first write")
	}
	if path != filepath.Join(dir, "frp-panel.service") {
		t.Fatalf("unexpected path %q", path)
	}
	want, err := assets.FS.ReadFile("systemd/frp-panel.service")
	if err != nil {
		t.Fatalf("canonical asset unreadable: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("written unit unreadable: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("written unit differs from the canonical embedded asset")
	}

	// Second run is a no-op.
	_, changed, err = writePanelUnit(dir)
	if err != nil {
		t.Fatalf("second writePanelUnit: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false when the file is already canonical")
	}

	// A drifted copy is repaired.
	drifted := []byte("[Unit]\nDescription=stale\n")
	if err := os.WriteFile(path, drifted, 0o644); err != nil {
		t.Fatal(err)
	}
	_, changed, err = writePanelUnit(dir)
	if err != nil {
		t.Fatalf("repair writePanelUnit: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when the existing unit drifted")
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatal("drifted unit was not restored to the canonical bytes")
	}
}
