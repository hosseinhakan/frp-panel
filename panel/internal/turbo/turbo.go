// Package turbo models the state the frp-turbo helper manages: the sysctl
// drop-in paths, the ZRAM env file (/etc/frp-panel/zram.env — byte-identical
// to the CLI's zram_on) and the parseable output of `frp-turbo status` /
// `frp-turbo zram-status`.
//
// The panel never applies sysctls itself — it drives the same helper + units
// the CLI does, so the two faces can never disagree about kernel state.
package turbo

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Host paths (relative to the filesystem root) frp-turbo manages.
const (
	DropinRelPath     = "/etc/sysctl.d/99-tunnel-turbo.conf" // written by apply, removed by revert
	ZRAMSysctlRelPath = "/etc/sysctl.d/99-frp-zram.conf"     // swappiness when zram active
	BBRModuleRelPath  = "/etc/modules-load.d/bbr.conf"       // loads tcp_bbr at boot
	ZramEnvName       = "zram.env"                           // inside /etc/frp-panel
)

// ZramAlgos are the compression algorithms accepted by zram-on.
var ZramAlgos = []string{"lz4", "zstd", "lzo", "lzo-rle"}

// DefaultZramSizeMB matches the CLI's zram-on default.
const DefaultZramSizeMB = 2048

// DefaultZramAlgo matches the CLI's zram-on default.
const DefaultZramAlgo = "lz4"

// ZramEnv mirrors /etc/frp-panel/zram.env. The CLI writes it with
// printf 'ZRAM_SIZE_MB=%s\nZRAM_ALGO=%s\n' — RenderZramEnv is byte-identical
// (two KEY=VALUE lines, no comment header).
type ZramEnv struct {
	SizeMB int
	Algo   string
}

func ValidZramAlgo(algo string) bool {
	for _, a := range ZramAlgos {
		if a == algo {
			return true
		}
	}
	return false
}

// Validate applies the same bounds the CLI implies: a sane RAM-backed size
// and a kernel-supported algorithm.
func (z ZramEnv) Validate() error {
	if z.SizeMB < 128 || z.SizeMB > 32768 {
		return fmt.Errorf("zram size must be between 128 and 32768 MB")
	}
	if !ValidZramAlgo(z.Algo) {
		return fmt.Errorf("zram algorithm %q not supported (want one of %s)",
			z.Algo, strings.Join(ZramAlgos, ", "))
	}
	return nil
}

// RenderZramEnv emits the env exactly as the CLI's zram_on does.
func RenderZramEnv(z ZramEnv) string {
	return fmt.Sprintf("ZRAM_SIZE_MB=%d\nZRAM_ALGO=%s\n", z.SizeMB, z.Algo)
}

// ReadZramEnv loads /etc/frp-panel/zram.env. ok is false when the file is
// missing (ZRAM not configured) or unreadable.
func ReadZramEnv(path string) (ZramEnv, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ZramEnv{}, false
	}
	z, err := ParseZramEnv(string(raw))
	if err != nil {
		return ZramEnv{}, false
	}
	return z, true
}

// ParseZramEnv parses the KEY=VALUE form (values are validated).
func ParseZramEnv(raw string) (ZramEnv, error) {
	z := ZramEnv{}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return ZramEnv{}, fmt.Errorf("zram.env: bad line %q", line)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "ZRAM_SIZE_MB":
			n, err := strconv.Atoi(val)
			if err != nil {
				return ZramEnv{}, fmt.Errorf("zram.env: ZRAM_SIZE_MB: %v", err)
			}
			z.SizeMB = n
		case "ZRAM_ALGO":
			z.Algo = val
		default:
			return ZramEnv{}, fmt.Errorf("zram.env: unknown key %q", key)
		}
		seen[key] = true
	}
	if !seen["ZRAM_SIZE_MB"] || !seen["ZRAM_ALGO"] {
		return ZramEnv{}, fmt.Errorf("zram.env: requires ZRAM_SIZE_MB and ZRAM_ALGO")
	}
	return z, nil
}

// ParseStatus turns the single line printed by `frp-turbo status`:
//
//	frp-turbo: qdisc=fq cc=bbr tcp_base_mss=1024 ... dropin=installed
//
// into a map. Empty map when the line doesn't match (helper missing etc.).
func ParseStatus(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "frp-turbo: ") {
			continue
		}
		for _, f := range strings.Fields(line[len("frp-turbo: "):]) {
			if k, v, ok := strings.Cut(f, "="); ok {
				res[k] = v
			}
		}
	}
	return res
}

// ZramStatus is the live zram swap state from `frp-turbo zram-status`
// (a `swapon --show=NAME,SIZE,USED,PRIORITY` line for zram0).
type ZramStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	SizeBytes int64  `json:"size_bytes"`
	UsedBytes int64  `json:"used_bytes"`
	Priority  int    `json:"priority"`
}

// ParseZramStatus parses the swapon line; ok=false when no zram swap is
// active ("frp-turbo: no zram swap active" or empty output).
func ParseZramStatus(out string) (ZramStatus, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 || !strings.Contains(fields[0], "zram") {
			continue
		}
		z := ZramStatus{Name: fields[0], Type: fields[1]}
		if v, err := ParseSize(fields[2]); err == nil {
			z.SizeBytes = v
		}
		if fields[3] != "" {
			if v, err := ParseSize(fields[3]); err == nil {
				z.UsedBytes = v
			}
		}
		if p, err := strconv.Atoi(fields[4]); err == nil {
			z.Priority = p
		}
		return z, true
	}
	return ZramStatus{}, false
}

// ParseSize parses swapon's human sizes: "2.0G", "123M", "512K", "4096B".
func ParseSize(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult, s = 1024, s[:len(s)-1]
	case 'M', 'm':
		mult, s = 1024*1024, s[:len(s)-1]
	case 'G', 'g':
		mult, s = 1024*1024*1024, s[:len(s)-1]
	case 'T', 't':
		mult, s = 1024*1024*1024*1024, s[:len(s)-1]
	case 'B', 'b':
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return int64(v * float64(mult)), nil
}
