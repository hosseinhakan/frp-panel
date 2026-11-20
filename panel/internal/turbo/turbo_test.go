package turbo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderZramEnvByteIdentity(t *testing.T) {
	// The CLI writes zram.env with printf 'ZRAM_SIZE_MB=%s\nZRAM_ALGO=%s\n'.
	want := "ZRAM_SIZE_MB=2048\nZRAM_ALGO=lz4\n"
	if got := RenderZramEnv(ZramEnv{SizeMB: 2048, Algo: "lz4"}); got != want {
		t.Fatalf("RenderZramEnv = %q, want %q", got, want)
	}
}

func TestZramEnvRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zram.env")
	if err := os.WriteFile(path, []byte(RenderZramEnv(ZramEnv{SizeMB: 4096, Algo: "zstd"})), 0o600); err != nil {
		t.Fatal(err)
	}
	z, ok := ReadZramEnv(path)
	if !ok || z.SizeMB != 4096 || z.Algo != "zstd" {
		t.Fatalf("ReadZramEnv = %+v ok=%v", z, ok)
	}
	if _, ok := ReadZramEnv(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing file must not parse")
	}
}

func TestParseZramEnv(t *testing.T) {
	z, err := ParseZramEnv("ZRAM_SIZE_MB=1024\nZRAM_ALGO=lzo\n")
	if err != nil || z.SizeMB != 1024 || z.Algo != "lzo" {
		t.Fatalf("ParseZramEnv = %+v err=%v", z, err)
	}
	if _, err := ParseZramEnv("ZRAM_SIZE_MB=1024\n"); err == nil {
		t.Fatal("missing ZRAM_ALGO must fail")
	}
	if _, err := ParseZramEnv("BROKEN\n"); err == nil {
		t.Fatal("garbage must fail")
	}
	if _, err := ParseZramEnv("ZRAM_SIZE_MB=abc\nZRAM_ALGO=lz4\n"); err == nil {
		t.Fatal("non-numeric size must fail")
	}
}

func TestZramValidate(t *testing.T) {
	cases := []struct {
		env   ZramEnv
		valid bool
	}{
		{ZramEnv{2048, "lz4"}, true},
		{ZramEnv{128, "zstd"}, true},
		{ZramEnv{64, "lz4"}, false},    // too small
		{ZramEnv{65536, "lz4"}, false}, // too big
		{ZramEnv{2048, "gzip"}, false}, // unsupported algo
		{ZramEnv{2048, ""}, false},
	}
	for _, c := range cases {
		err := c.env.Validate()
		if c.valid != (err == nil) {
			t.Fatalf("Validate(%+v) = %v, want valid=%v", c.env, err, c.valid)
		}
	}
}

func TestParseStatus(t *testing.T) {
	out := "frp-turbo: qdisc=fq cc=bbr tcp_base_mss=1024 rmem_max=33554432 wmem_max=33554432 somaxconn=65535 ip_forward=1 dropin=installed\n"
	m := ParseStatus(out)
	want := map[string]string{
		"qdisc": "fq", "cc": "bbr", "tcp_base_mss": "1024",
		"rmem_max": "33554432", "wmem_max": "33554432", "somaxconn": "65535",
		"ip_forward": "1", "dropin": "installed",
	}
	if len(m) != len(want) {
		t.Fatalf("ParseStatus got %d keys, want %d", len(m), len(want))
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("ParseStatus[%q] = %q, want %q", k, m[k], v)
		}
	}
	if got := ParseStatus("some unrelated output"); len(got) != 0 {
		t.Fatalf("non-matching output should be empty, got %v", got)
	}
}

func TestParseZramStatus(t *testing.T) {
	out := "/dev/zram0                              partition   2.0G   123M  100\n"
	z, ok := ParseZramStatus(out)
	if !ok {
		t.Fatal("active zram not detected")
	}
	if z.Name != "/dev/zram0" || z.Type != "partition" {
		t.Fatalf("name/type = %q/%q", z.Name, z.Type)
	}
	if z.SizeBytes != 2*1024*1024*1024 {
		t.Fatalf("size = %d, want %d", z.SizeBytes, 2*1024*1024*1024)
	}
	if z.UsedBytes != 123*1024*1024 {
		t.Fatalf("used = %d, want %d", z.UsedBytes, 123*1024*1024)
	}
	if z.Priority != 100 {
		t.Fatalf("priority = %d", z.Priority)
	}

	if _, ok := ParseZramStatus("frp-turbo: no zram swap active\n"); ok {
		t.Fatal("inactive output must not report a status")
	}
	if _, ok := ParseZramStatus(""); ok {
		t.Fatal("empty output must not report a status")
	}
	// Other swap devices present but no zram.
	if _, ok := ParseZramStatus("/swapfile                              file     1.0G   10M  -2\n"); ok {
		t.Fatal("non-zram swap must be ignored")
	}
}

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"2.0G", 2 * 1024 * 1024 * 1024},
		{"123M", 123 * 1024 * 1024},
		{"512K", 512 * 1024},
		{"4096B", 4096},
		{"768", 768},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if err != nil || got != c.want {
			t.Fatalf("ParseSize(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	if _, err := ParseSize("bogus"); err == nil {
		t.Fatal("bogus size must fail")
	}
}

// Paths constants must stay in sync with the frp-turbo helper (the CLI and
// the panel both reason about these locations).
func TestPathConstants(t *testing.T) {
	if DropinRelPath != "/etc/sysctl.d/99-tunnel-turbo.conf" {
		t.Fatal("dropin path drifted from frp-turbo")
	}
	if !strings.HasPrefix(ZRAMSysctlRelPath, "/etc/sysctl.d/") || !strings.HasPrefix(BBRModuleRelPath, "/etc/modules-load.d/") {
		t.Fatal("turbo paths outside expected dirs")
	}
}
