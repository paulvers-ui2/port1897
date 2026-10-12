// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Command genasn turns iptoasn.com's public-domain IP-to-ASN tables into the
// fixed-size binary files fswin embeds (asn_windows.go, geoip/README.md). It
// runs in CI, where the network is open; a plain source checkout keeps empty
// placeholders instead. The input is iptoasn's TSV, one range per line:
//
//	range_start \t range_end \t AS_number \t country_code \t AS_description
//
// Usage: genasn <ip2asn-v4.tsv> <ip2asn-v6.tsv> <out-dir>
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type rng struct {
	start, end netip.Addr
	asn        uint32
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: genasn <ip2asn-v4.tsv> <ip2asn-v6.tsv> <out-dir>")
		os.Exit(2)
	}
	for _, f := range []struct {
		in     string
		out    string
		keyLen int
		v6     bool
	}{
		{os.Args[1], "asn.v4", 4, false},
		{os.Args[2], "asn.v6", 16, true},
	} {
		ranges, err := parseFile(f.in, f.v6)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genasn: %s: %v\n", f.in, err)
			os.Exit(1)
		}
		data := build(ranges, f.keyLen)
		out := filepath.Join(os.Args[3], f.out)
		if err := os.WriteFile(out, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "genasn: %s: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("genasn: %s: %d ranges, %d bytes\n", out, len(ranges), len(data))
	}
}

func parseFile(path string, v6 bool) ([]rng, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a build-time input path given on the command line
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f, v6)
}

// parse reads the TSV, keeping ranges of the wanted address family and
// dropping malformed lines. ASN 0 (iptoasn's "Not routed") is kept so those
// ranges resolve to no network.
func parse(r io.Reader, v6 bool) ([]rng, error) {
	var out []rng
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) < 3 {
			continue
		}
		start, err1 := netip.ParseAddr(strings.TrimSpace(cols[0]))
		end, err2 := netip.ParseAddr(strings.TrimSpace(cols[1]))
		as, err3 := strconv.ParseUint(strings.TrimSpace(cols[2]), 10, 32)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		if start.Is6() != v6 || end.Is6() != v6 || start.Is4In6() || end.Is4In6() {
			continue
		}
		if end.Less(start) {
			continue
		}
		out = append(out, rng{start: start, end: end, asn: uint32(as)})
	}
	return out, sc.Err()
}

// build turns ranges into fswin's records: addr (keyLen bytes) + 4-byte
// big-endian ASN, ascending by address. Overlapping ranges are dropped, and
// a 0 record fills the gap after a range when the next one does not start
// right after it, so an address between ranges resolves to no network.
func build(ranges []rng, keyLen int) []byte {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start.Less(ranges[j].start) })
	var out []byte
	var lastEnd netip.Addr
	have := false
	put := func(a netip.Addr, as uint32) {
		if keyLen == 4 {
			b := a.As4()
			out = append(out, b[:]...)
		} else {
			b := a.As16()
			out = append(out, b[:]...)
		}
		out = append(out, byte(as>>24), byte(as>>16), byte(as>>8), byte(as))
	}
	for _, r := range ranges {
		if have {
			if !lastEnd.Less(r.start) {
				continue // overlaps or duplicates a range already written
			}
			if gap := lastEnd.Next(); gap.IsValid() && gap.Less(r.start) {
				put(gap, 0) // unrouted space before this range
			}
		}
		put(r.start, r.asn)
		lastEnd, have = r.end, true
	}
	// addresses past the last range resolve to no network
	if have {
		if tail := lastEnd.Next(); tail.IsValid() {
			put(tail, 0)
		}
	}
	return out
}
