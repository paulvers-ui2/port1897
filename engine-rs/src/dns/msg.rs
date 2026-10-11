// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS message helpers on hickory-proto, after firestack's xdns: the query
//! name and type as the resolver reads them, EDNS padding, the BlockAll
//! answer and the summary's answer data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};

/// Shorter is not a DNS message (xdns.MinDNSPacketSize).
pub const MIN_PACKET: usize = 12 + 5;
/// The EDNS payload size firestack asks for.
pub const MAX_PACKET: u16 = 4096;
/// RFC 8467's block size for query padding.
const PAD_BLOCK: usize = 128;
/// The TTL of BlockAll answers: firestack sets 0 so that Windows and apps
/// do not keep blocked answers once the rules change.
pub const BLOCK_TTL: u32 = 0;

pub fn parse(b: &[u8]) -> Result<Message, String> {
    if b.len() < MIN_PACKET {
        return Err("dns: packet too small".to_string());
    }
    Message::from_vec(b).map_err(|e| format!("dns: {e}"))
}

pub fn pack(m: &Message) -> Result<Vec<u8>, String> {
    m.to_vec().map_err(|e| format!("dns: {e}"))
}

/// The first question's name, lowercased, without the trailing dot ("."
/// for the root), as firestack's resolver passes it on. "" without one.
pub fn qname(m: &Message) -> String {
    let Some(q) = m.queries.first() else {
        return String::new();
    };
    let s = q.name().to_ascii();
    if s.is_empty() || s == "." {
        return ".".to_string();
    }
    s.trim_end_matches('.').to_ascii_lowercase()
}

/// The first question's type; 0 without one.
pub fn qtype(m: &Message) -> u16 {
    m.queries.first().map(|q| u16::from(q.query_type())).unwrap_or(0)
}

pub fn rcode(m: &Message) -> i32 {
    u16::from(m.metadata.response_code) as i32
}

/// Whether the query asks for DNSSEC records (the DO bit).
pub fn dnssec_requested(m: &Message) -> bool {
    m.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
}

/// Adds RFC 7830 padding to a 128-byte boundary unless the query has
/// some, with an EDNS record of 4096 bytes if it had none (xdns's
/// AddEDNS0PaddingIfNoneFound).
pub fn pad_query(m: &mut Message) {
    if m.edns.is_none() {
        let mut e = Edns::new();
        e.set_max_payload(MAX_PACKET);
        m.edns = Some(e);
    }
    if m.edns.as_ref().is_some_and(|e| e.option(EdnsCode::Padding).is_some()) {
        return;
    }
    let Ok(len) = m.to_vec().map(|v| v.len()) else {
        return;
    };
    let pad = (PAD_BLOCK - (len + 4) % PAD_BLOCK) % PAD_BLOCK;
    if pad == 0 {
        return;
    }
    if let Some(e) = m.edns.as_mut() {
        e.options_mut().insert(EdnsOption::Unknown(u16::from(EdnsCode::Padding), vec![0; pad]));
    }
}

/// An empty answer to q: its header with the response bit, recursion
/// available if desired, and its EDNS size and DO bit (xdns's
/// EmptyResponseFromMessage). None without a question.
pub fn empty_response(q: &Message) -> Option<Message> {
    q.queries.first()?;
    let mut m = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
    // hickory's Metadata is non-exhaustive, so the query's is copied and
    // the answer's own flags set on it
    m.metadata = q.metadata;
    m.metadata.message_type = MessageType::Response;
    m.metadata.recursion_available = q.metadata.recursion_desired;
    m.metadata.recursion_desired = false;
    m.metadata.checking_disabled = false;
    m.metadata.authentic_data = false;
    m.queries = q.queries.clone();
    if let Some(e) = q.edns.as_ref() {
        let mut out = Edns::new();
        out.set_max_payload(e.max_payload().max(512));
        out.set_dnssec_ok(e.flags().dnssec_ok);
        m.edns = Some(out);
    }
    Some(m)
}

/// What BlockAll answers (xdns's RefusedResponseFromMessage): NOERROR
/// with 0.0.0.0 for A, :: for AAAA, nothing for HTTPS/SVCB and a HINFO
/// record for anything else.
pub fn block_answer(q: &Message) -> Option<Message> {
    let mut m = empty_response(q)?;
    m.metadata.response_code = ResponseCode::NoError;
    let question = &q.queries[0];
    let name = question.name().clone();
    let rd = match question.query_type() {
        RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
        RecordType::HTTPS | RecordType::SVCB => {
            m.additionals.clear();
            None
        }
        _ => Some(RData::HINFO(HINFO::new("These are not the queries you are".to_string(), "looking for".to_string()))),
    };
    if let Some(rd) = rd {
        let mut r = Record::from_rdata(name, BLOCK_TTL, rd);
        r.dns_class = DNSClass::IN;
        m.answers = vec![r];
    }
    Some(m)
}

/// SERVFAIL for q, with its question echoed: what the resolver answers
/// when no transport could answer, as firestack does. None without a
/// question.
pub fn servfail(q: &Message) -> Option<Message> {
    let mut m = empty_response(q)?;
    m.metadata.response_code = ResponseCode::ServFail;
    Some(m)
}

/// The A and AAAA addresses in the answer section.
pub fn ips(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

pub fn ip_csv(ips: &[IpAddr]) -> String {
    ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",")
}

/// The largest answer TTL (xdns.RTtl); 0 without answers.
pub fn rttl(m: &Message) -> u32 {
    m.answers.iter().map(|r| r.ttl).max().unwrap_or(0)
}

/// Sets every answer record's TTL (xdns.WithTtl for the answer section).
pub fn with_ttl(m: &mut Message, ttl: u32) {
    for r in m.answers.iter_mut() {
        r.ttl = ttl;
    }
}

fn svcb_hints(s: &SVCB, v4: &mut Vec<String>, v6: &mut Vec<String>) {
    for (_, v) in &s.svc_params {
        match v {
            SvcParamValue::Ipv4Hint(h) => v4.extend(h.0.iter().map(|a| a.0.to_string())),
            SvcParamValue::Ipv6Hint(h) => v6.extend(h.0.iter().map(|a| a.0.to_string())),
            _ => {}
        }
    }
}

/// The answer data the journal shows (xdns.GetInterestingRData): the
/// addresses for A/AAAA (and HTTPS/SVCB hints), else the first record of
/// a kind it knows. "--" for no message.
pub fn interesting_rdata(m: Option<&Message>) -> String {
    let Some(m) = m else {
        return "--".to_string();
    };
    let mut ips: Vec<String> = Vec::new();
    let qt = m.queries.first().map(|q| q.query_type());
    if matches!(qt, Some(RecordType::HTTPS) | Some(RecordType::SVCB)) {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for r in &m.answers {
            match &r.data {
                RData::HTTPS(h) => svcb_hints(&h.0, &mut v4, &mut v6),
                RData::SVCB(s) => svcb_hints(s, &mut v4, &mut v6),
                _ => {}
            }
        }
        ips.extend(v4);
        ips.extend(v6);
    }
    let hinted = !ips.is_empty();
    for r in &m.answers {
        match &r.data {
            RData::A(a) => ips.push(a.0.to_string()),
            RData::AAAA(a) => ips.push(a.0.to_string()),
            RData::NS(n) => return n.0.to_string(),
            RData::TXT(t) => {
                return match t.txt_data.first() {
                    Some(s) => String::from_utf8_lossy(s).into_owned(),
                    None => r.to_string(),
                };
            }
            RData::SOA(s) => return s.rname.to_string(),
            RData::HINFO(h) => return String::from_utf8_lossy(&h.os).into_owned(),
            RData::SRV(s) => return s.target.to_string(),
            RData::CAA(c) => return String::from_utf8_lossy(&c.value).into_owned(),
            RData::MX(mx) => return mx.exchange.to_string(),
            RData::HTTPS(_) | RData::SVCB(_) if !hinted => {
                if ips.is_empty() {
                    return r.data.to_string();
                }
                ips.push(r.data.to_string());
            }
            _ => {}
        }
    }
    ips.join(",")
}

/// A query with id 0x1234 and recursion desired (tests).
#[cfg(test)]
pub(crate) fn test_query(name: &str, t: RecordType) -> Message {
    use hickory_proto::op::{OpCode, Query};
    use std::str::FromStr;
    let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(hickory_proto::rr::Name::from_str(name).unwrap(), t));
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn query(name: &str, t: RecordType) -> Message {
        test_query(name, t)
    }

    #[test]
    fn names() {
        let m = query("WWW.Example.COM.", RecordType::AAAA);
        assert_eq!(qname(&m), "www.example.com");
        assert_eq!(qtype(&m), 28);
        assert_eq!(qname(&query(".", RecordType::NS)), ".");
        let empty = Message::new(1, MessageType::Query, OpCode::Query);
        assert_eq!(qname(&empty), "");
        assert_eq!(qtype(&empty), 0);
        assert!(parse(&[0; 12]).is_err());
    }

    #[test]
    fn padding() {
        for n in ["a.b", "example.com", "a-much-longer-name.of-some-domain.example.org"] {
            let mut m = query(n, RecordType::A);
            pad_query(&mut m);
            let b = pack(&m).unwrap();
            assert_eq!(b.len() % PAD_BLOCK, 0, "{n}: {}", b.len());
            let e = m.edns.as_ref().unwrap();
            assert_eq!(e.max_payload(), 4096);
            // padded once only
            let before = b.len();
            pad_query(&mut m);
            assert_eq!(pack(&m).unwrap().len(), before);
            // and it survives a round trip
            let back = parse(&b).unwrap();
            assert!(back.edns.unwrap().option(EdnsCode::Padding).is_some());
        }
    }

    #[test]
    fn block_answers() {
        let mut q = query("ads.example.com.", RecordType::A);
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_dnssec_ok(true);
        q.edns = Some(e);
        let a = block_answer(&q).unwrap();
        assert_eq!(a.metadata.id, 0x1234);
        assert_eq!(a.metadata.message_type, MessageType::Response);
        assert!(a.metadata.recursion_available);
        assert!(!a.metadata.recursion_desired);
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].ttl, 0);
        assert_eq!(interesting_rdata(Some(&a)), "0.0.0.0");
        assert!(a.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(a.edns.as_ref().unwrap().max_payload(), 1232);
        // round trip through the wire
        let back = parse(&pack(&a).unwrap()).unwrap();
        assert_eq!(ips(&back), vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);

        let a6 = block_answer(&query("ads.example.com.", RecordType::AAAA)).unwrap();
        assert_eq!(interesting_rdata(Some(&a6)), "::");
        let h = block_answer(&query("ads.example.com.", RecordType::HTTPS)).unwrap();
        assert!(h.answers.is_empty());
        let mx = block_answer(&query("ads.example.com.", RecordType::MX)).unwrap();
        assert_eq!(mx.answers[0].record_type(), RecordType::HINFO);
        assert_eq!(interesting_rdata(Some(&mx)), "looking for");
        assert!(block_answer(&Message::new(1, MessageType::Query, OpCode::Query)).is_none());
    }

    #[test]
    fn rdata() {
        let mut a = empty_response(&query("example.com.", RecordType::A)).unwrap();
        let n = Name::from_str("example.com.").unwrap();
        a.answers.push(Record::from_rdata(n.clone(), 300, RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_str("e.cdn.net.").unwrap()))));
        a.answers.push(Record::from_rdata(n.clone(), 60, RData::A(A(Ipv4Addr::new(93, 184, 215, 14)))));
        a.answers.push(Record::from_rdata(n.clone(), 30, RData::A(A(Ipv4Addr::new(93, 184, 215, 15)))));
        assert_eq!(interesting_rdata(Some(&a)), "93.184.215.14,93.184.215.15");
        assert_eq!(rttl(&a), 300);
        with_ttl(&mut a, 15);
        assert_eq!(rttl(&a), 15);
        assert_eq!(interesting_rdata(None), "--");
        let mut mx = empty_response(&query("example.com.", RecordType::MX)).unwrap();
        mx.answers.push(Record::from_rdata(n, 60, RData::MX(hickory_proto::rr::rdata::MX::new(10, Name::from_str("mail.example.com.").unwrap()))));
        assert_eq!(interesting_rdata(Some(&mx)), "mail.example.com.");
    }
}
