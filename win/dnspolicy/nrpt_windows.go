// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package dnspolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// NRPT rules (the Name Resolution Policy Table) are registry keys, one per
// rule; Windows' DNS Client watches them and applies a change by itself.
// Tailscale and Proton VPN write them this way. This package used to run
// PowerShell's Add-DnsClientNrptRule instead: about 1.5 s a call, two calls
// per start and one per stop.
var (
	root = registry.LOCAL_MACHINE // tests use HKCU
	// rules this PC sets (Add-DnsClientNrptRule's, and ours)
	localRules = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// rules from group policy (read only)
	policyRules = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
)

const (
	// our rule's key: one fixed id, so a rule left by a crash is found and
	// replaced, never doubled
	ruleKey = "{4A0F3C2E-8B71-4D5A-9E26-AF1D7C3B5E90}"
	tag     = "AuroraVPN"
	// ConfigOptions 0x8: answer from GenericDNSServers. Version 2 is what
	// Add-DnsClientNrptRule writes.
	configGenericServers = 0x8
	ruleVersion          = 2
)

// ours tells our rules apart: the fixed key, or the comment of one that
// PowerShell made ("port1897": the app's name before 0.3).
func ours(r rule) bool {
	return strings.EqualFold(r.key, ruleKey) || r.comment == tag || r.comment == "port1897" ||
		r.display == tag || r.display == "port1897"
}

// Add replaces any of our rules with one sending all names (".") to server,
// then flushes the DNS cache. If the process dies without Remove, the rule
// stays and DNS fails until Remove (or Add) runs again.
func Add(server netip.Addr) error {
	if err := removeOurs(); err != nil {
		return err
	}
	k, _, err := registry.CreateKey(root, localRules+`\`+ruleKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("dnspolicy: add: %w", err)
	}
	defer k.Close()
	err = errors.Join(
		k.SetDWordValue("Version", ruleVersion),
		k.SetStringsValue("Name", []string{"."}),
		k.SetStringValue("GenericDNSServers", server.String()),
		k.SetDWordValue("ConfigOptions", configGenericServers),
		k.SetStringValue("Comment", tag),
		k.SetStringValue("DisplayName", tag),
		k.SetStringValue("IPSECCARestriction", ""),
	)
	if err != nil {
		_ = registry.DeleteKey(root, localRules+`\`+ruleKey)
		return fmt.Errorf("dnspolicy: add: %w", err)
	}
	flush()
	return nil
}

// Remove deletes our rules and flushes the DNS cache.
func Remove() error {
	err := removeOurs()
	flush()
	return err
}

// Others lists catch-all (".") rules that are not ours, such as another
// VPN's, as "DisplayName (Comment)"; they compete with ours for every query.
func Others() ([]string, error) {
	var out []string
	for _, path := range []string{localRules, policyRules} {
		rules, err := list(path)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if !ours(r) && slices.Contains(r.names, ".") {
				out = append(out, fmt.Sprintf("%s (%s)", r.display, r.comment))
			}
		}
	}
	return out, nil
}

func removeOurs() error {
	rules, err := list(localRules)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range rules {
		if !ours(r) {
			continue
		}
		if err := registry.DeleteKey(root, localRules+`\`+r.key); err != nil && !errors.Is(err, registry.ErrNotExist) {
			errs = append(errs, fmt.Errorf("dnspolicy: remove %s: %w", r.key, err))
		}
	}
	return errors.Join(errs...)
}

type rule struct {
	key              string
	names            []string // namespaces: "." for all names
	comment, display string
}

// list reads the rules under path; none when the key does not exist.
func list(path string) ([]rule, error) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dnspolicy: %s: %w", path, err)
	}
	defer k.Close()
	keys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("dnspolicy: %s: %w", path, err)
	}
	var rules []rule
	for _, key := range keys {
		rk, err := registry.OpenKey(root, path+`\`+key, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		r := rule{key: key}
		r.names, _, _ = rk.GetStringsValue("Name")
		r.comment, _, _ = rk.GetStringValue("Comment")
		r.display, _, _ = rk.GetStringValue("DisplayName")
		rk.Close()
		rules = append(rules, r)
	}
	return rules, nil
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// flush empties the DNS cache, as ipconfig /flushdns does, so no answer from
// before the change is used after it.
func flush() {
	if procDnsFlushResolverCache.Find() == nil {
		_, _, _ = syscall.SyscallN(procDnsFlushResolverCache.Addr())
	}
}
