package dnssec

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// FIRESTACK PATCH P9: a DS record whose digest type miekg/dns cannot compute
// (GOST R 34.11-94 = 3, or an unassigned value) used to make ToDS return nil,
// which upstream dereferenced, crashing the lookup. Such a DS must simply not
// match (RFC 4035 §5.2), leaving the zone Insecure rather than panicking.
func TestVerifyDNSKEYsUnsupportedDigestDoesNotPanic(t *testing.T) {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	if _, err := k.Generate(256); err != nil {
		t.Fatal(err)
	}
	for _, digestType := range []uint8{dns.GOST94, 99} {
		if k.ToDS(digestType) != nil {
			t.Skipf("miekg/dns now supports digest type %d; test premise gone", digestType)
		}
		ds := &dns.DS{
			Hdr:        dns.RR_Header{Name: "example.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
			KeyTag:     k.KeyTag(),
			Algorithm:  k.Algorithm,
			DigestType: digestType,
			Digest:     "00",
		}
		state, err := verifyDNSKEYs(context.Background(), &result{}, []dns.RR{k}, []*dns.DS{ds})
		if state != Insecure || !errors.Is(err, ErrKeysNotFound) {
			t.Errorf("digest type %d: got (%v, %v), want (Insecure, ErrKeysNotFound)", digestType, state, err)
		}
	}
}
