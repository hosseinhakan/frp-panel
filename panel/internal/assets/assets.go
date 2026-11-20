// Package assets embeds the systemd unit templates and helper scripts shipped
// by the FRP Tunnel Suite. The copies in this directory are canonical: the bash
// CLI (frp-setup.sh) embeds byte-identical heredocs, and scripts/check-sync.sh
// fails CI if the two ever drift.
package assets

import "embed"

// FS contains:
//
//	systemd/*.service  — frps@.service, frpc@.service, gre-tunnel@.service,
//	                     tunnel-turbo.service, frp-zram.service,
//	                     frp-watchdog.service, frp-panel.service
//	helpers/*          — frp-gre, frp-turbo, frp-watchdog
//
//go:embed systemd helpers
var FS embed.FS
