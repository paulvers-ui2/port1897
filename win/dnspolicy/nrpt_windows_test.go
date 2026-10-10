// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package dnspolicy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// sandbox points the package at keys under HKCU, so the test reads and
// writes rules without touching this PC's DNS.
func sandbox(t *testing.T) string {
	t.Helper()
	base := `Software\AuroraVPNTest\` + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	oldRoot, oldLocal, oldPolicy := root, localRules, policyRules
	root, localRules, policyRules = registry.CURRENT_USER, base+`\local`, base+`\policy`
	t.Cleanup(func() {
		root, localRules, policyRules = oldRoot, oldLocal, oldPolicy
		deleteTree(t, registry.CURRENT_USER, base)
	})
	return base
}

func deleteTree(t *testing.T, r registry.Key, path string) {
	k, err := registry.OpenKey(r, path, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, s := range subs {
			deleteTree(t, r, path+`\`+s)
		}
	}
	_ = registry.DeleteKey(r, path)
}

// another adds a rule as PowerShell's Add-DnsClientNrptRule writes it.
func another(t *testing.T, path, key, display, comment string, names ...string) {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path+`\`+key, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := k.SetStringsValue("Name", names); err != nil {
		t.Fatal(err)
	}
	_ = k.SetStringValue("DisplayName", display)
	_ = k.SetStringValue("Comment", comment)
	_ = k.SetStringValue("GenericDNSServers", "10.2.0.1")
	_ = k.SetDWordValue("ConfigOptions", 8)
	_ = k.SetDWordValue("Version", 2)
}

func TestAddWritesTheRuleAsWindowsReadsIt(t *testing.T) {
	sandbox(t)
	if err := Add(netip.MustParseAddr("10.111.222.3")); err != nil {
		t.Fatal(err)
	}
	k, err := registry.OpenKey(root, localRules+`\`+ruleKey, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	names, _, _ := k.GetStringsValue("Name")
	servers, _, _ := k.GetStringValue("GenericDNSServers")
	opts, _, _ := k.GetIntegerValue("ConfigOptions")
	ver, _, _ := k.GetIntegerValue("Version")
	comment, _, _ := k.GetStringValue("Comment")
	if !slices.Equal(names, []string{"."}) || servers != "10.111.222.3" || opts != 8 || ver != 2 || comment != tag {
		t.Fatalf("rule: names %q, servers %q, options %d, version %d, comment %q", names, servers, opts, ver, comment)
	}
}

func TestOthersAndRemove(t *testing.T) {
	sandbox(t)
	// another VPN's catch-all rule, a split rule, and two of ours left over
	another(t, localRules, "{11111111-1111-1111-1111-111111111111}", "", "Force all DNS requests via Proton VPN", ".")
	another(t, localRules, "{22222222-2222-2222-2222-222222222222}", "corp", "", ".corp.example")
	another(t, localRules, "{33333333-3333-3333-3333-333333333333}", "", "port1897", ".")
	another(t, policyRules, "{44444444-4444-4444-4444-444444444444}", "GP VPN", "from policy", ".")
	if err := Add(netip.MustParseAddr("10.111.222.3")); err != nil {
		t.Fatal(err)
	}

	others, err := Others()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{" (Force all DNS requests via Proton VPN)", "GP VPN (from policy)"}
	if !slices.Equal(others, want) {
		t.Fatalf("Others = %q, want %q", others, want)
	}

	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	left, err := list(localRules)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range left {
		keys = append(keys, r.key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}"}) {
		t.Fatalf("after Remove: %q; ours (the fixed key and the port1897 one) must be gone, the others kept", keys)
	}
}

func TestNoRulesKey(t *testing.T) {
	sandbox(t)
	if others, err := Others(); err != nil || len(others) != 0 {
		t.Fatalf("Others without the key: %q, %v", others, err)
	}
	if err := Remove(); err != nil {
		t.Fatalf("Remove without the key: %v", err)
	}
}
