package resolver

import (
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"
)

// FIRESTACK PATCH (P4): upstream used a package-level sync.Once, so the
// result could never be refreshed after a network change (Wi-Fi <-> mobile).
var ipv6CheckMu sync.Mutex
var ipv6Check = new(sync.Once)

var ipv6Answered atomic.Bool
var ipv6Available atomic.Bool

// IPv6Available return true if IPv6 Internet connectivity is found.
// If the check has not been performed, it won't block, and (initially) will return false.
func IPv6Available() bool {
	if ipv6Answered.Load() {
		return ipv6Available.Load()
	}
	if ipv6Available.Load() {
		return true
	}
	ipv6CheckMu.Lock()
	once := ipv6Check
	ipv6CheckMu.Unlock()
	go once.Do(UpdateIPv6Availability)
	return false
}

// ResetIPv6Availability forgets the cached result so the next call to
// IPv6Available re-probes. Call it when the underlying network changes.
func ResetIPv6Availability() {
	ipv6CheckMu.Lock()
	ipv6Check = new(sync.Once)
	ipv6Answered.Store(false)
	ipv6Available.Store(false)
	ipv6CheckMu.Unlock()
}

// UpdateIPv6Availability sense checks if we can get a DNS response from an IPv6 address.
func UpdateIPv6Availability() {
	defer ipv6Answered.Store(true)

	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeNS)

	client := &dns.Client{
		Timeout: 500 * time.Millisecond,
		Dialer:  newDialer(), // FIRESTACK PATCH (P1)
	}

	// Tries:
	// 	k.root-servers.net
	// 	e.root-servers.net.
	// 	a.root-servers.net.
	for _, address := range []string{"2001:7fd::1", "2001:500:a8::e", "2001:503:ba3e::2:30"} {
		ipv6Address := fmt.Sprintf("[%s]:53", address)

		_, _, err := client.Exchange(msg, ipv6Address)
		ipv6Available.Store(err == nil)
		if err == nil {
			return
		}
	}
}
