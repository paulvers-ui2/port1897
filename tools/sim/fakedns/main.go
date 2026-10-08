// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// fakedns is a plain DNS server for the simulations in tools/sim: it
// answers every query the same way, so fswin -dns proxy can be shown a
// misbehaving upstream.
//
//	fakedns -addr 127.0.0.1:5353 -mode servfail
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5353", "UDP and TCP address to listen on")
	mode := flag.String("mode", "ok", "ok (A 192.0.2.10), servfail, refused, nxdomain or drop (never answer)")
	flag.Parse()

	rcode := map[string]int{"ok": dns.RcodeSuccess, "servfail": dns.RcodeServerFailure, "refused": dns.RcodeRefused, "nxdomain": dns.RcodeNameError}
	rc, ok := rcode[*mode]
	if !ok && *mode != "drop" {
		fmt.Fprintln(os.Stderr, "fakedns: unknown -mode", *mode)
		os.Exit(2)
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, q *dns.Msg) {
		log.Printf("fakedns: %s %v from %s", *mode, q.Question, w.RemoteAddr())
		if *mode == "drop" {
			return
		}
		m := new(dns.Msg)
		m.SetRcode(q, rc)
		if rc == dns.RcodeSuccess && len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 10),
			})
		}
		_ = w.WriteMsg(m)
	})

	errc := make(chan error, 2)
	for _, nw := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *addr, Net: nw}
		go func() { errc <- srv.ListenAndServe() }()
	}
	log.Printf("fakedns: %s on %s", *mode, *addr)
	log.Fatal(<-errc)
}
