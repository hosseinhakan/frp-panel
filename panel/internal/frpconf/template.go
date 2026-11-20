package frpconf

import (
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// FRP's Go-template port expansion (the mikeesierrah profile):
//
//	{{- range $_, $v := parseNumberRangePair "22,6000-6006" "22,6000-6006" }}
//	[[proxies]]
//	name = "tcp-{{ $v.First }}"
//	type = "tcp"
//	localIP = "127.0.0.1"
//	localPort = {{ $v.First }}
//	remotePort = {{ $v.Second }}
//	transport.useEncryption = false
//	transport.useCompression = false
//	{{- end }}
//
// This file turns those blocks into the same expanded model the panel uses for
// plain [[proxies]] configs, and preserves the range input so re-rendering
// keeps the compact layout.

type rangeBlock struct {
	Local    string
	Remote   string
	Type     string
	LocalIP  string
	Encrypt  bool
	Compress bool
}

func isRangeStart(line string) (local, remote string, ok bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "{{") || !strings.Contains(t, "parseNumberRangePair") {
		return "", "", false
	}
	// Everything between the two quoted arguments.
	first := strings.IndexByte(t, '"')
	if first < 0 {
		return "", "", false
	}
	second := strings.IndexByte(t[first+1:], '"')
	if second < 0 {
		return "", "", false
	}
	local = t[first+1 : first+1+second]
	rest := t[first+1+second+1:]
	third := strings.IndexByte(rest, '"')
	if third < 0 {
		return "", "", false
	}
	fourth := strings.IndexByte(rest[third+1:], '"')
	if fourth < 0 {
		return "", "", false
	}
	remote = rest[third+1 : third+1+fourth]
	return local, remote, true
}

// stripRangeBlocks removes every parseNumberRangePair block and returns the
// remaining TOML plus the parsed block metadata. ok is false when the input
// contains no range block or a block is unterminated.
func stripRangeBlocks(raw []byte) ([]byte, []rangeBlock, bool) {
	lines := strings.Split(string(raw), "\n")
	out := make([]string, 0, len(lines))
	var blocks []rangeBlock
	var body []string
	inBlock := false
	cur := rangeBlock{}

	for _, line := range lines {
		if !inBlock {
			if local, remote, ok := isRangeStart(line); ok {
				inBlock = true
				cur = rangeBlock{Local: local, Remote: remote, Type: "tcp", LocalIP: "127.0.0.1"}
				body = body[:0]
				continue
			}
			out = append(out, line)
			continue
		}
		if strings.Contains(line, "{{") && strings.Contains(line, "end") {
			parseRangeBody(&cur, body)
			blocks = append(blocks, cur)
			inBlock = false
			continue
		}
		body = append(body, line)
	}
	if inBlock || len(blocks) == 0 {
		return raw, nil, false
	}
	return []byte(strings.Join(out, "\n")), blocks, true
}

func parseRangeBody(block *rangeBlock, body []string) {
	for _, line := range body {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "type = "):
			if v, ok := quotedValue(t); ok {
				block.Type = v
			}
		case strings.HasPrefix(t, "localIP = "):
			if v, ok := quotedValue(t); ok && v != "" {
				block.LocalIP = v
			}
		case strings.HasPrefix(t, "transport.useEncryption"):
			block.Encrypt = strings.Contains(t, "true")
		case strings.HasPrefix(t, "transport.useCompression"):
			block.Compress = strings.Contains(t, "true")
		}
	}
}

func quotedValue(line string) (string, bool) {
	first := strings.IndexByte(line, '"')
	if first < 0 {
		return "", false
	}
	second := strings.IndexByte(line[first+1:], '"')
	if second < 0 {
		return "", false
	}
	return line[first+1 : first+1+second], true
}

// parseRangeClient decodes a range-template config into the managed model.
func parseRangeClient(raw []byte) (*ClientConfig, error) {
	stripped, blocks, ok := stripRangeBlocks(raw)
	if !ok {
		return nil, tomlErrNotRange
	}
	cfg := &ClientConfig{}
	if err := toml.Unmarshal(stripped, cfg); err != nil {
		return nil, err
	}
	cfg.RangeTemplate = true
	cfg.RangeLocal = blocks[0].Local
	cfg.RangeRemote = blocks[0].Remote
	for _, blk := range blocks {
		specs, err := ParsePortSpecs(blk.Local)
		if err != nil {
			return nil, err
		}
		typ := blk.Type
		if typ == "" {
			typ = "tcp"
		}
		localIP := blk.LocalIP
		if localIP == "" {
			localIP = "127.0.0.1"
		}
		for _, s := range specs {
			for p := s.Start; p <= s.End; p++ {
				cfg.Proxies = append(cfg.Proxies, newProxy(typ, p, localIP, blk.Encrypt, blk.Compress))
			}
		}
	}
	return cfg, nil
}

type rangeErr string

func (e rangeErr) Error() string { return string(e) }

const tomlErrNotRange = rangeErr("frpconf: not a parseNumberRangePair template")
