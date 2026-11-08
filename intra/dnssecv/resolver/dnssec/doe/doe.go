package doe

import (
	"context"
	"github.com/miekg/dns"
)

type DenialOfExistenceNSEC struct {
	ctx     context.Context
	zone    string
	records []*dns.NSEC
}

type DenialOfExistenceNSEC3 struct {
	ctx     context.Context
	zone    string
	records []*dns.NSEC3
}

func NewDenialOfExistenceNSEC(ctx context.Context, zone string, records []*dns.NSEC) *DenialOfExistenceNSEC {
	return &DenialOfExistenceNSEC{
		ctx,
		zone,
		records,
	}
}

func NewDenialOfExistenceNSEC3(ctx context.Context, zone string, records []*dns.NSEC3) *DenialOfExistenceNSEC3 {
	checkRecords := make([]*dns.NSEC3, 0, len(records))
	for _, r := range records {
		// We must ignore records that have unknown hash or flag values.
		if r.Hash != dns.SHA1 {
			continue
		}
		// FIRESTACK PATCH (P11): upstream also tested r.Flags < 0, which is
		// always false for a uint8 (staticcheck SA4003). Only the opt-out flag
		// (bit 0) may be set; any other value is unknown and must be ignored.
		if r.Flags > 1 {
			continue
		}

		checkRecords = append(checkRecords, r)
	}
	return &DenialOfExistenceNSEC3{
		ctx,
		zone,
		checkRecords,
	}
}

//----------------------------------------------------------

func (doe *DenialOfExistenceNSEC) Empty() bool {
	return len(doe.records) == 0
}

func (doe *DenialOfExistenceNSEC3) Empty() bool {
	return len(doe.records) == 0
}
