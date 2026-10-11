// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! JSON read the way Go's encoding/json reads it into fswin's structs, so
//! that what the Go engine took (rules files, API bodies) the Rust one takes
//! too: object keys match field names regardless of case, a later duplicate
//! key wins, `null` leaves a field at its zero value, unknown keys are
//! skipped, and invalid UTF-8 inside strings becomes U+FFFD. A value of the
//! wrong type fails the whole decode, as it does for fswin's callers.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::golike;

/// A JSON value with its object keys in document order, duplicates kept.
#[derive(Debug, Clone, PartialEq)]
pub enum JValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<JValue>),
    Object(Vec<(String, JValue)>),
}

impl<'de> Deserialize<'de> for JValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(JVisitor)
    }
}

struct JVisitor;

impl<'de> Visitor<'de> for JVisitor {
    type Value = JValue;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<JValue, E> {
        Ok(JValue::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<JValue, E> {
        Ok(JValue::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<JValue, E> {
        Ok(JValue::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<JValue, E> {
        serde_json::Number::from_f64(v).map(JValue::Number).ok_or_else(|| E::custom("bad number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<JValue, E> {
        Ok(JValue::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<JValue, E> {
        Ok(JValue::String(v))
    }
    fn visit_unit<E>(self) -> Result<JValue, E> {
        Ok(JValue::Null)
    }
    fn visit_none<E>(self) -> Result<JValue, E> {
        Ok(JValue::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<JValue, D::Error> {
        JValue::deserialize(d)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JValue, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element()? {
            out.push(v);
        }
        Ok(JValue::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JValue, A::Error> {
        let mut out = Vec::new();
        while let Some((k, v)) = map.next_entry::<String, JValue>()? {
            out.push((k, v));
        }
        Ok(JValue::Object(out))
    }
}

impl JValue {
    /// Go's name for the JSON kind, as its type errors word it.
    fn kind(&self) -> &'static str {
        match self {
            JValue::Null => "null",
            JValue::Bool(_) => "bool",
            JValue::Number(_) => "number",
            JValue::String(_) => "string",
            JValue::Array(_) => "array",
            JValue::Object(_) => "object",
        }
    }
}

/// `json.Unmarshal`: one value, nothing but white space after it.
pub fn unmarshal(data: &[u8]) -> Result<JValue, String> {
    let text = String::from_utf8_lossy(data);
    serde_json::from_str::<JValue>(&text).map_err(|e| e.to_string())
}

/// `json.NewDecoder(http.MaxBytesReader(w, body, limit)).Decode`: the first
/// value, whatever follows it, provided it is complete within limit bytes.
pub fn decode_first(data: &[u8], limit: usize) -> Result<JValue, String> {
    let within = &data[..data.len().min(limit)];
    let text = String::from_utf8_lossy(within);
    let mut stream = serde_json::Deserializer::from_str(&text).into_iter::<JValue>();
    match stream.next() {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) if e.is_eof() && data.len() > limit => Err("http: request body too large".to_string()),
        Some(Err(e)) => Err(e.to_string()),
        None if data.len() > limit => Err("http: request body too large".to_string()),
        None => Err("EOF".to_string()),
    }
}

/// The fields of a JSON object as Go's decoder assigns them to a struct.
pub struct Obj<'a> {
    entries: &'a [(String, JValue)],
    /// the Go type, for error messages: "main.ruleSet"
    path: String,
}

impl<'a> Obj<'a> {
    /// v as the struct type named ty; None for JSON null (the zero value).
    pub fn of(v: &'a JValue, ty: &str) -> Result<Option<Obj<'a>>, String> {
        match v {
            JValue::Null => Ok(None),
            JValue::Object(e) => Ok(Some(Obj { entries: e, path: ty.to_string() })),
            other => Err(format!("json: cannot unmarshal {} into Go value of type {ty}", other.kind())),
        }
    }

    /// The value for field name: the last key that equals it, ignoring case.
    pub fn get(&self, name: &str) -> Option<&'a JValue> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == name || golike::equal_fold(k, name))
            .map(|(_, v)| v)
    }

    fn type_err(&self, v: &JValue, field: &str, ty: &str) -> String {
        format!("json: cannot unmarshal {} into Go struct field {}.{field} of type {ty}", v.kind(), self.path)
    }

    pub fn string(&self, name: &str) -> Result<String, String> {
        match self.get(name) {
            None | Some(JValue::Null) => Ok(String::new()),
            Some(JValue::String(s)) => Ok(s.clone()),
            Some(v) => Err(self.type_err(v, name, "string")),
        }
    }

    pub fn bool(&self, name: &str) -> Result<bool, String> {
        match self.get(name) {
            None | Some(JValue::Null) => Ok(false),
            Some(JValue::Bool(b)) => Ok(*b),
            Some(v) => Err(self.type_err(v, name, "bool")),
        }
    }

    pub fn int(&self, name: &str) -> Result<i64, String> {
        match self.get(name) {
            None | Some(JValue::Null) => Ok(0),
            Some(v) => as_int(v).ok_or_else(|| self.type_err(v, name, "int")),
        }
    }

    /// A nested struct field; None when missing or null.
    pub fn obj(&self, name: &str, ty: &str) -> Result<Option<Obj<'a>>, String> {
        match self.get(name) {
            None | Some(JValue::Null) => Ok(None),
            Some(JValue::Object(e)) => Ok(Some(Obj { entries: e, path: format!("{}.{name}", self.path) })),
            Some(v) => Err(self.type_err(v, name, ty)),
        }
    }

    /// A slice field: its elements; empty when missing or null.
    pub fn array(&self, name: &str, ty: &str) -> Result<&'a [JValue], String> {
        match self.get(name) {
            None | Some(JValue::Null) => Ok(&[]),
            Some(JValue::Array(a)) => Ok(a),
            Some(v) => Err(self.type_err(v, name, ty)),
        }
    }

    /// A map field: its entries in document order; empty when missing or null.
    pub fn map(&self, name: &str, ty: &str) -> Result<&'a [(String, JValue)], String> {
        match self.get(name) {
            None | Some(JValue::Null) => Ok(&[]),
            Some(JValue::Object(e)) => Ok(e),
            Some(v) => Err(self.type_err(v, name, ty)),
        }
    }

    /// An element of a slice or map field, as a struct of type ty.
    pub fn elem(&self, field: &str, v: &'a JValue, ty: &str) -> Result<Option<Obj<'a>>, String> {
        match v {
            JValue::Null => Ok(None),
            JValue::Object(e) => Ok(Some(Obj { entries: e, path: format!("{}.{field}", self.path) })),
            other => Err(self.type_err(other, field, ty)),
        }
    }

    /// An element of a []string field.
    pub fn elem_string(&self, field: &str, v: &JValue) -> Result<String, String> {
        match v {
            JValue::Null => Ok(String::new()),
            JValue::String(s) => Ok(s.clone()),
            other => Err(self.type_err(other, field, "string")),
        }
    }

    /// An element of a []int field.
    pub fn elem_int(&self, field: &str, v: &JValue) -> Result<i64, String> {
        match v {
            JValue::Null => Ok(0),
            other => as_int(other).ok_or_else(|| self.type_err(other, field, "int")),
        }
    }
}

/// A JSON number that Go's strconv.ParseInt takes: no fraction or exponent.
fn as_int(v: &JValue) -> Option<i64> {
    match v {
        JValue::Number(n) => n.as_i64(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_like_go() {
        let v = unmarshal(br#"{"Mode":"block","mode":"allow","ROUTE":"wgapp1","extra":1}"#).unwrap();
        let o = Obj::of(&v, "main.appRule").unwrap().unwrap();
        assert_eq!(o.string("mode").unwrap(), "allow", "the later key wins");
        assert_eq!(o.string("route").unwrap(), "wgapp1", "case does not matter");
        assert_eq!(o.string("noProxy").unwrap(), "", "missing is zero");
        let v = unmarshal(br#"{"mode":null,"allowUntil":null}"#).unwrap();
        let o = Obj::of(&v, "main.appRule").unwrap().unwrap();
        assert_eq!(o.string("mode").unwrap(), "");
        assert_eq!(o.int("allowUntil").unwrap(), 0);
    }

    #[test]
    fn types_like_go() {
        let v = unmarshal(br#"{"port":443.0,"name":5,"n":-7,"big":9223372036854775808}"#).unwrap();
        let o = Obj::of(&v, "main.ipRule").unwrap().unwrap();
        assert!(o.int("port").is_err(), "443.0 is not an int to Go");
        assert_eq!(
            o.string("name").unwrap_err(),
            "json: cannot unmarshal number into Go struct field main.ipRule.name of type string"
        );
        assert_eq!(o.int("n").unwrap(), -7);
        assert!(o.int("big").is_err());
        assert!(Obj::of(&unmarshal(b"[]").unwrap(), "main.ruleSet").is_err());
        assert!(Obj::of(&unmarshal(b"null").unwrap(), "main.ruleSet").unwrap().is_none());
    }

    #[test]
    fn unmarshal_and_decode() {
        assert!(unmarshal(b"{} x").is_err(), "Unmarshal wants nothing after the value");
        assert!(decode_first(b"{} x", 4096).is_ok(), "Decode takes the first value only");
        assert_eq!(decode_first(b"", 4096).unwrap_err(), "EOF");
        assert_eq!(decode_first(b"  ", 4096).unwrap_err(), "EOF");
        let big = format!("{{\"app\":\"{}\"}}", "a".repeat(5000));
        assert_eq!(decode_first(big.as_bytes(), 4096).unwrap_err(), "http: request body too large");
        let padded = format!("{{\"app\":\"x\"}}{}", " ".repeat(5000));
        assert!(decode_first(padded.as_bytes(), 4096).is_ok(), "complete within the limit");
        // invalid UTF-8 in a string: U+FFFD, as Go
        let v = unmarshal(b"{\"app\":\"a\xffb\"}").unwrap();
        let o = Obj::of(&v, "x").unwrap().unwrap();
        assert_eq!(o.string("app").unwrap(), "a\u{fffd}b");
    }
}
