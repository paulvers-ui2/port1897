// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package dnspolicy

import (
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// ours matches our NRPT rules, so stale ones (after a crash) can be found:
// they carry tag, or "port1897", the app's name before 0.3.
const (
	tag  = "AuroraVPN"
	ours = "$_.Comment -in 'AuroraVPN','port1897'"
)

// Add replaces any of our rules with one sending all names (".") to server,
// then flushes the DNS cache. If the process dies without Remove, the rule
// stays and DNS fails until Remove (or Add) runs again.
func Add(server netip.Addr) error {
	return ps(fmt.Sprintf(
		`Get-DnsClientNrptRule | Where-Object { %s } | Remove-DnsClientNrptRule -Force; `+
			`Add-DnsClientNrptRule -Namespace '.' -NameServers '%s' -Comment '%s' | Out-Null; `+
			`Clear-DnsClientCache`, ours, server, tag))
}

// Remove deletes our rules and flushes the DNS cache.
func Remove() error {
	return ps(fmt.Sprintf(
		`Get-DnsClientNrptRule | Where-Object { %s } | Remove-DnsClientNrptRule -Force; `+
			`Clear-DnsClientCache`, ours))
}

// Others lists catch-all (".") rules that are not ours, such as another
// VPN's; they compete with ours for every query.
func Others() ([]string, error) {
	out, err := psOut(fmt.Sprintf(
		`Get-DnsClientNrptRule | Where-Object { $_.Namespace -contains '.' -and -not (%s) } | `+
			`ForEach-Object { "$($_.DisplayName) ($($_.Comment))" }`, ours))
	if err != nil {
		return nil, err
	}
	var rules []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			rules = append(rules, l)
		}
	}
	return rules, nil
}

func ps(script string) error {
	_, err := psOut(script)
	return err
}

func psOut(script string) (string, error) {
	// Windows PowerShell from System32, running our own fixed scripts
	out, err := exec.Command(powershell(), "-NoProfile", "-NonInteractive", //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		"-Command", "$ErrorActionPreference = 'Stop'; "+script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dnspolicy: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// powershell is Windows PowerShell from System32, never one found through
// PATH, which the user's environment sets.
func powershell() string {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return "powershell.exe"
}
