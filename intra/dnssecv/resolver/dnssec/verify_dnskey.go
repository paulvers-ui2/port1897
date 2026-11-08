package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func verifyDNSKEYs(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {

	zoneKeys := extractRecords[*dns.DNSKEY](keys)
	if len(zoneKeys) == 0 {
		return Insecure, ErrKeysNotFound
	}

	//---

	// keySigningKeys are the zone's keys have a matching DS record from the parent zone.
	// These are the keys that are allowed to sign the DNSKEY rrset.
	keySigningKeys := make([]*dns.DNSKEY, 0, len(dsRecordsFromParent))
	for _, d := range dsRecordsFromParent {
		for _, k := range zoneKeys {
			if d.Algorithm != k.Algorithm || d.KeyTag != k.KeyTag() {
				continue
			}
			// FIRESTACK PATCH (P9): d.DigestType comes from the parent's DS
			// record on the network. ToDS returns nil for digest types
			// miekg/dns doesn't implement (e.g. GOST), and upstream
			// dereferenced it: a zone publishing such a DS crashed the lookup.
			// An undigestable DS simply doesn't match (RFC 4035 §5.2 allows
			// ignoring DS records with unsupported digest types).
			computed := k.ToDS(d.DigestType)
			if computed != nil && strings.EqualFold(d.Digest, computed.Digest) {
				keySigningKeys = append(keySigningKeys, k)
				break
			}
		}
	}

	if len(keySigningKeys) == 0 {
		return Insecure, ErrKeysNotFound
	}

	//---

	keySignatures, err := authenticate(r.zone.Name(), keys, keySigningKeys, answerSection)

	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	r.keys = keySignatures

	if err = keySignatures.Verify(); err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	return Unknown, nil
}
