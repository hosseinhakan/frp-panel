package api

import (
	"strings"
	"testing"

	"github.com/frp-suite/panel/internal/assets"
)

// The embedded helpers must never carry the two sysctls that hurt bulk video
// throughput on long-haul links, and frp-gre must never delete another GRE
// tunnel behind the operator's back.
func TestCanonicalHelpersAreStreamingSafeAndNonDestructive(t *testing.T) {
	for _, name := range []string{"helpers/frp-gre", "helpers/frp-turbo"} {
		raw, err := assets.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(raw)
		for _, bad := range []string{
			"net.ipv4.tcp_notsent_lowat = 16384",
			"net.ipv4.tcp_fastopen = 3",
			"purge_remote_conflicts",
		} {
			if strings.Contains(body, bad) {
				t.Errorf("%s still contains %q", name, bad)
			}
		}
		if !strings.Contains(body, "net.ipv4.tcp_notsent_lowat=4294967295") {
			t.Errorf("%s does not reset tcp_notsent_lowat to the kernel default", name)
		}
	}
}

// The canonical gre-tunnel drop-in must keep the tuned-but-safe values.
func TestGRETuningKeepsSafeKeys(t *testing.T) {
	raw, err := assets.FS.ReadFile("helpers/frp-gre")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"net.core.default_qdisc = fq",
		"net.ipv4.tcp_congestion_control = bbr",
		"net.core.rmem_max = 16777216",
		"net.core.wmem_max = 16777216",
		"net.core.netdev_max_backlog = 16384",
		"net.core.somaxconn = 65535",
		"net.ipv4.tcp_slow_start_after_idle = 0",
		"net.ipv4.tcp_mtu_probing = 1",
		"net.ipv4.tcp_base_mss = 1024",
		"net.ipv4.conf.all.rp_filter = 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("frp-gre tuning lost %q", want)
		}
	}
}
